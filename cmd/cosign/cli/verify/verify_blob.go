//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"bytes"
	"context"
	"crypto"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-openapi/runtime"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/tuf"

	ctypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// nolint
func VerifyBlobCmd(ctx context.Context, ko options.KeyOpts, certRef, certEmail,
	certOidcIssuer, certChain, sigRef, blobRef, certGithubWorkflowTrigger, certGithubWorkflowSha,
	certGithubWorkflowName,
	certGithubWorkflowRepository,
	certGithubWorkflowRef string, enforceSCT bool) error {
	var verifier signature.Verifier
	var cert *x509.Certificate

	if !options.OneOf(ko.KeyRef, ko.Sk, certRef) && !options.EnableExperimental() && ko.BundlePath == "" {
		return &options.PubKeyParseError{}
	}

	sig, err := signatures(sigRef, ko.BundlePath)
	if err != nil {
		return err
	}

	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		return err
	}

	co := &cosign.CheckOpts{
		CertEmail:                    certEmail,
		CertOidcIssuer:               certOidcIssuer,
		CertGithubWorkflowTrigger:    certGithubWorkflowTrigger,
		CertGithubWorkflowSha:        certGithubWorkflowSha,
		CertGithubWorkflowName:       certGithubWorkflowName,
		CertGithubWorkflowRepository: certGithubWorkflowRepository,
		CertGithubWorkflowRef:        certGithubWorkflowRef,
		EnforceSCT:                   enforceSCT,
	}
	if options.EnableExperimental() {
		if ko.RekorURL != "" {
			rekorClient, err := rekor.NewClient(ko.RekorURL)
			if err != nil {
				return fmt.Errorf("creating Rekor client: %w", err)
			}
			co.RekorClient = rekorClient
		}
		co.RootCerts, err = fulcio.GetRoots()
		if err != nil {
			return fmt.Errorf("getting Fulcio roots: %w", err)
		}
		co.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
	}

	// Keys are optional!
	switch {
	case ko.KeyRef != "":
		verifier, err = sigs.PublicKeyFromKeyRef(ctx, ko.KeyRef)
		if err != nil {
			return fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := verifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case ko.Sk:
		sk, err := pivkey.GetKeyWithSlot(ko.Slot)
		if err != nil {
			return fmt.Errorf("opening piv token: %w", err)
		}
		defer sk.Close()
		verifier, err = sk.Verifier()
		if err != nil {
			return fmt.Errorf("loading public key from token: %w", err)
		}
	case certRef != "":
		cert, err = loadCertFromFileOrURL(certRef)
		if err != nil {
			return err
		}
		if certChain == "" {
			// If no certChain is passed, the Fulcio root certificate will be used
			verifier, err = cosign.ValidateAndUnpackCert(cert, co)
			if err != nil {
				return err
			}
		} else {
			// Verify certificate with chain
			chain, err := loadCertChainFromFileOrURL(certChain)
			if err != nil {
				return err
			}
			verifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
			if err != nil {
				return err
			}
		}
	case ko.BundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(ko.BundlePath)
		if err != nil {
			return err
		}
		if b.Cert == "" {
			return fmt.Errorf("bundle does not contain cert for verification, please provide public key")
		}
		// cert can either be a cert or public key
		certBytes := []byte(b.Cert)
		if isb64(certBytes) {
			certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
		}
		cert, err = loadCertFromPEM(certBytes)
		if err != nil {
			// check if cert is actually a public key
			verifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
		} else {
			verifier, err = cosign.ValidateAndUnpackCert(cert, co)
			if err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	// No certificate is provided: search by artifact sha in the TLOG.
	case options.EnableExperimental():
		uuids, err := cosign.FindTLogEntriesByPayload(ctx, co.RekorClient, blobBytes)
		if err != nil {
			return err
		}

		if len(uuids) == 0 {
			return errors.New("could not find a tlog entry for provided blob")
		}

		// Iterate through and try to find a matching Rekor entry.
		for _, u := range uuids {
			tlogEntry, err := cosign.GetTlogEntry(ctx, co.RekorClient, u)
			if err != nil {
				continue
			}

			// Note that this will error out if the TLOG entry was signed with a
			// raw public key. Again, using search on artifact sha is unreliable.
			certs, err := extractCerts(tlogEntry)
			if err != nil {
				continue
			}

			cert := certs[0]
			verifier, err := cosign.ValidateAndUnpackCert(cert, co)
			if err != nil {
				continue
			}

			// We found a succesful Rekor entry!
			if err := verifyBlob(ctx, ko, co, blobBytes, sig, verifier, cert, tlogEntry); err == nil {
				fmt.Fprintln(os.Stderr, "Verified OK")
				return nil
			}
		}

		// No successful Rekor entry found.
		fmt.Fprintln(os.Stderr, `WARNING: No valid entries were found in rekor to verify this blob.

Transparency log support for blobs is experimental, and occasionally an entry isn't found even if one exists.

We recommend requesting the certificate/signature from the original signer of this blob and manually verifying with cosign verify-blob --cert [cert] --signature [signature].`)
		return fmt.Errorf("could not find a valid tlog entry for provided blob, found %d invalid entries", len(uuids))

	}

	// Use the DSSE verifier if the payload is a DSSE with the In-Toto format.
	if isIntotoDSSE(blobBytes) {
		verifier = dsse.WrapVerifier(verifier)
	}

	// Verify Blob main entry point. This will perform the following:
	//     1. Verifies the signature on the blob using the provided verifier.
	//     2. Checks for transparency log entry presence:
	//          a. Verifies the Rekor entry in the bundle, if provided. OR
	//          b. Uses the provided Rekor entry (may have been retrieved through Redis search) OR
	//          c. If experimental mode is enabled, does a Rekor online lookup for an entry.
	//     3. If the certificate is expired, uses the verified Rekor entry to check expiration.
	if err := verifyBlob(ctx, ko, co, blobBytes, sig, verifier, cert, nil); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

func verifyBlob(ctx context.Context, ko options.KeyOpts, co *cosign.CheckOpts,
	blobBytes []byte, sig string, verifier signature.Verifier,
	cert *x509.Certificate,
	e *models.LogEntryAnon) error {
	// 1. Verify the signature.
	if err := verifier.VerifySignature(bytes.NewReader([]byte(sig)), bytes.NewReader(blobBytes)); err != nil {
		return err
	}

	// This is the signature creation time. Without a transparency log entry timestamp,
	// we can only use the current time as a bound.
	validityTime := time.Now()
	// 2. Checks for transparency log entry presence:
	switch {
	// a. We have a local bundle.
	case ko.BundlePath != "":
		bundle, err := verifyRekorBundle(ctx, ko.BundlePath, cert, co.RekorClient)
		if err != nil {
			return err
		}
		validityTime = time.Unix(bundle.IntegratedTime, 0)
		fmt.Fprintf(os.Stderr, "tlog entry verified offline\n")
	// b. We can make an online lookup to the transparency log.
	case options.EnableExperimental() && e == nil:
		// 2b. If experimental mode is enabled, does a Rekor online lookup for an entry.
		var err error
		if cert == nil {
			pub, err := co.SigVerifier.PublicKey(co.PKOpts...)
			if err != nil {
				return err
			}
			e, err = tlogFindPublicKey(ctx, co.RekorClient, blobBytes, sig, pub)
		} else {
			e, err = tlogFindCertificate(ctx, co.RekorClient, blobBytes, sig, cert)
		}
		if err != nil {
			return err
		}
		fallthrough
	// We are provided a log entry, possibly from above, or search.
	case e != nil:
		if err := cosign.VerifyTLogEntry(ctx, co.RekorClient, e); err != nil {
			return err
		}

		uuid, err := cosign.ComputeLeafHash(e)
		if err != nil {
			return err
		}

		validityTime = time.Unix(*e.IntegratedTime, 0)
		fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %s index: %d\n", hex.EncodeToString(uuid), *e.LogIndex)
	}

	// 3. If the certificate is expired, uses the verified Rekor entry to check expiration.
	if cert == nil {
		return nil
	}

	return cosign.CheckExpiry(cert, validityTime)
}

func tlogFindPublicKey(ctx context.Context, rekorClient *client.Rekor,
	blobBytes []byte, sig string, pub crypto.PublicKey) (*models.LogEntryAnon, error) {
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	if err != nil {
		return nil, err
	}
	return tlogFindEntry(ctx, rekorClient, blobBytes, sig, pemBytes)
}

func tlogFindCertificate(ctx context.Context, rekorClient *client.Rekor,
	blobBytes []byte, sig string, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	pemBytes, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}
	return tlogFindEntry(ctx, rekorClient, blobBytes, sig, pemBytes)
}

func tlogFindEntry(ctx context.Context, client *client.Rekor,
	blobBytes []byte, sig string, pem []byte) (*models.LogEntryAnon, error) {
	b64sig := base64.StdEncoding.EncodeToString([]byte(sig))
	e, err := cosign.FindTlogEntry(ctx, client, b64sig, blobBytes, pem)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// signatures returns the raw signature
func signatures(sigRef string, bundlePath string) (string, error) {
	var targetSig []byte
	var err error
	switch {
	case sigRef != "":
		targetSig, err = blob.LoadFileOrURL(sigRef)
		if err != nil {
			if !os.IsNotExist(err) {
				// ignore if file does not exist, it can be a base64 encoded string as well
				return "", err
			}
			targetSig = []byte(sigRef)
		}
	case bundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
		if err != nil {
			return "", err
		}
		targetSig = []byte(b.Base64Signature)
	default:
		return "", fmt.Errorf("missing flag '--signature'")
	}

	var sig, b64sig string
	if isb64(targetSig) {
		b64sig = string(targetSig)
		sigBytes, _ := base64.StdEncoding.DecodeString(b64sig)
		sig = string(sigBytes)
	} else {
		sig = string(targetSig)
		b64sig = base64.StdEncoding.EncodeToString(targetSig)
	}
	return sig, nil
}

func payloadBytes(blobRef string) ([]byte, error) {
	var blobBytes []byte
	var err error
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return nil, err
	}
	return blobBytes, nil
}

// TODO: RekorClient can be removed when SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY
// is removed.
func verifyRekorBundle(ctx context.Context, bundlePath string, cert *x509.Certificate, rekorClient *client.Rekor) (*bundle.RekorPayload, error) {
	b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
	if err != nil {
		return nil, err
	}
	if b.Bundle == nil {
		return nil, fmt.Errorf("rekor entry is not available")
	}
	publicKeys, err := cosign.GetRekorPubs(ctx, rekorClient)
	if err != nil {
		return nil, fmt.Errorf("retrieving rekor public key: %w", err)
	}

	pubKey, ok := publicKeys[b.Bundle.Payload.LogID]
	if !ok {
		return nil, errors.New("rekor log public key not found for payload")
	}
	err = cosign.VerifySET(b.Bundle.Payload, b.Bundle.SignedEntryTimestamp, pubKey.PubKey)
	if err != nil {
		return nil, err
	}
	if pubKey.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
	}

	return &b.Bundle.Payload, nil
}

func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}

// isIntotoDSSE checks whether a payload is a Dead Simple Signing Envelope with the In-Toto format.
func isIntotoDSSE(blobBytes []byte) bool {
	DSSEenvelope := ssldsse.Envelope{}
	if err := json.Unmarshal(blobBytes, &DSSEenvelope); err != nil {
		return false
	}
	if DSSEenvelope.PayloadType != ctypes.IntotoPayloadType {
		return false
	}

	return true
}
