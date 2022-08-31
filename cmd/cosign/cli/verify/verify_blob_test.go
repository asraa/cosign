// Copyright 2022 The Sigstore Authors.
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/internal/pkg/cosign/rekor/mock"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/test"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestSignaturesRef(t *testing.T) {
	sig := "a=="
	b64sig := "YT09"
	tests := []struct {
		description string
		sigRef      string
		shouldErr   bool
	}{
		{
			description: "raw sig",
			sigRef:      sig,
		},
		{
			description: "encoded sig",
			sigRef:      b64sig,
		}, {
			description: "empty ref",
			shouldErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			gotSig, err := signatures(test.sigRef, "")
			if test.shouldErr && err != nil {
				return
			}
			if test.shouldErr {
				t.Fatal("should have received an error")
			}
			if gotSig != sig {
				t.Fatalf("unexpected signature, expected: %s got: %s", sig, gotSig)
			}
		})
	}
}

func TestSignaturesBundle(t *testing.T) {
	td := t.TempDir()
	fp := filepath.Join(td, "file")

	sig := "a=="
	b64sig := "YT09"

	// save as a LocalSignedPayload to the file
	lsp := cosign.LocalSignedPayload{
		Base64Signature: b64sig,
	}
	contents, err := json.Marshal(lsp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fp, contents, 0644); err != nil {
		t.Fatal(err)
	}

	gotSig, err := signatures("", fp)
	if err != nil {
		t.Fatal(err)
	}
	if gotSig != sig {
		t.Fatalf("unexpected signature, expected: %s got: %s", sig, gotSig)
	}
}

func TestIsIntotoDSSEWithEnvelopes(t *testing.T) {
	tts := []struct {
		envelope     dsse.Envelope
		isIntotoDSSE bool
	}{
		{
			envelope: dsse.Envelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     base64.StdEncoding.EncodeToString([]byte("This is a test")),
				Signatures:  []dsse.Signature{},
			},
			isIntotoDSSE: true,
		},
	}
	for _, tt := range tts {
		envlopeBytes, _ := json.Marshal(tt.envelope)
		got := isIntotoDSSE(envlopeBytes)
		if got != tt.isIntotoDSSE {
			t.Fatalf("unexpected envelope content")
		}
	}
}

func TestIsIntotoDSSEWithBytes(t *testing.T) {
	tts := []struct {
		envelope     []byte
		isIntotoDSSE bool
	}{
		{
			envelope:     []byte("This is no valid"),
			isIntotoDSSE: false,
		},
		{
			envelope:     []byte("MEUCIQDBmE1ZRFjUVic1hzukesJlmMFG1JqWWhcthnhawTeBNQIga3J9/WKsNlSZaySnl8V360bc2S8dIln2/qo186EfjHA="),
			isIntotoDSSE: false,
		},
	}
	for _, tt := range tts {
		envlopeBytes, _ := json.Marshal(tt.envelope)
		got := isIntotoDSSE(envlopeBytes)
		if got != tt.isIntotoDSSE {
			t.Fatalf("unexpected envelope content")
		}
	}
}

// Does not test identity options, only blob verification with different
// options.
func TestVerifyBlob(t *testing.T) {
	ctx := context.Background()

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadECDSASignerVerifier(leafPriv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// Generate expired and unexpired certificates
	identity := "hello@foo.com"
	issuer := "issuer"
	rootCert, rootPriv, _ := test.GenerateRootCa()
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	unexpiredLeafCert, _ := test.GenerateLeafCertWithExpiration(identity, issuer,
		time.Now().Add(time.Hour), leafPriv, rootCert, rootPriv)
	expiredLeafCert, _ := test.GenerateLeafCertWithExpiration(identity, issuer,
		time.Now().Add(-time.Hour), leafPriv, rootCert, rootPriv)

	var makeSignature = func(blob []byte) string {
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}
		return string(sig)
	}
	blobBytes := []byte("foo")

	tts := []struct {
		name        string
		blob        []byte
		signature   string
		sigVerifier signature.Verifier
		cert        *x509.Certificate
		bundlePath  string
		// If online lookups to Rekor are enabled
		experimental bool
		// The rekor entry response when Rekor is enabled
		rekorEntry *models.LogEntry
		shouldErr  bool
	}{
		{
			name:         "valid signature with public key",
			blob:         blobBytes,
			signature:    makeSignature(blobBytes),
			sigVerifier:  signer,
			experimental: false,
			shouldErr:    false,
		},
		{
			name:         "valid signature with public key - experimental",
			blob:         blobBytes,
			signature:    makeSignature(blobBytes),
			sigVerifier:  signer,
			experimental: true,
			shouldErr:    false,
		},
		{
			name:         "invalid signature with public key",
			blob:         blobBytes,
			signature:    makeSignature([]byte("bar")),
			sigVerifier:  signer,
			experimental: false,
			shouldErr:    true,
		},
		{
			name:         "invalid signature with public key - experimental",
			blob:         blobBytes,
			signature:    makeSignature([]byte("bar")),
			sigVerifier:  signer,
			experimental: true,
			shouldErr:    true,
		},
		{
			name:         "valid signature with unexpired certificate",
			blob:         blobBytes,
			signature:    makeSignature(blobBytes),
			sigVerifier:  signer,
			cert:         unexpiredLeafCert,
			experimental: false,
			shouldErr:    false,
		},
		{
			name:         "invalid signature with unexpired certificate",
			blob:         blobBytes,
			signature:    makeSignature([]byte("bar")),
			sigVerifier:  signer,
			cert:         unexpiredLeafCert,
			experimental: false,
			shouldErr:    true,
		},
		{
			name:         "valid signature with unexpired certificate - experimental & no rekor entry found",
			blob:         blobBytes,
			signature:    makeSignature(blobBytes),
			cert:         unexpiredLeafCert,
			sigVerifier:  signer,
			experimental: true,
			shouldErr:    false,
		},
		{
			name:         "valid signature with unexpired certificate - experimental & rekor entry found",
			blob:         blobBytes,
			signature:    makeSignature(blobBytes),
			cert:         unexpiredLeafCert,
			experimental: true,
			rekorEntry:   nil, // TODO
			shouldErr:    false,
		},
		{
			name:         "valid signature with expired certificate",
			blob:         blobBytes,
			signature:    makeSignature(blobBytes),
			cert:         expiredLeafCert,
			sigVerifier:  signer,
			experimental: false,
			shouldErr:    true,
		},
		{
			name:         "valid signature with expired certificate - experimental good rekor lookup",
			blob:         blobBytes,
			signature:    "",
			sigVerifier:  signer,
			experimental: true,
			rekorEntry:   nil, // TODO
			shouldErr:    false,
		},
		{
			name:         "valid signature with expired certificate - experimental bad rekor lookup",
			blob:         blobBytes,
			signature:    "",
			sigVerifier:  signer,
			experimental: true,
			rekorEntry:   nil, // TODO
			shouldErr:    true,
		},
		{
			name:         "valid signature with expired certificate - good bundle",
			blob:         blobBytes,
			signature:    "",
			sigVerifier:  signer,
			experimental: false,
			bundlePath:   "", // TODO
			shouldErr:    false,
		},
		{
			name:         "valid signature with expired certificate - bad SET bundle",
			blob:         blobBytes,
			signature:    "",
			sigVerifier:  signer,
			experimental: false,
			bundlePath:   "", // TODO
			shouldErr:    true,
		},
		{
			name:         "valid signature with expired certificate - experimental good bundle",
			blob:         blobBytes,
			signature:    "",
			sigVerifier:  signer,
			experimental: true,
			bundlePath:   "", // TODO
			shouldErr:    false,
		},
		{
			name:         "valid signature with expired certificate - experimental bad SET bundle",
			blob:         blobBytes,
			signature:    "",
			sigVerifier:  signer,
			experimental: true,
			bundlePath:   "", // TODO
			shouldErr:    true,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			var mClient client.Rekor
			mClient.Entries = &mock.EntriesClient{
				Entries: *tt.rekorEntry,
			}
			co := &cosign.CheckOpts{
				SigVerifier: tt.sigVerifier,
				RootCerts:   rootPool,
			}
			// if expermental is enabled, add RekorClient to co.
			if tt.experimental {
				co.RekorClient = &mClient
			}

			err := verifyBlob(ctx, co, tt.blob, tt.signature, tt.cert, tt.bundlePath, nil)
			if (err != nil) != tt.shouldErr {
				t.Fatalf("verifyBlob()= %s, expected shouldErr=%t ", err, tt.shouldErr)
			}
		})
	}
}

func TestVerifyBlobCmdWithBundle(t *testing.T) {
	td := t.TempDir()

	// Note that COSIGN_EXPERIMENTAL=1 is not needed for offline bundles.

	identity := "hello@foo.com"
	issuer := "issuer"

	// Generate certificate chain
	rootCert, rootPriv, _ := test.GenerateRootCa()
	rootPemCert, _ := cryptoutils.MarshalCertificateToPEM(rootCert)
	subCert, subPriv, _ := test.GenerateSubordinateCa(rootCert, rootPriv)
	subPemCert, _ := cryptoutils.MarshalCertificateToPEM(subCert)
	leafCert, leafPriv, _ := test.GenerateLeafCert(identity, issuer, subCert, subPriv)
	leafPemCert, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	// Write certificate chain to disk
	var chain []byte
	chain = append(chain, subPemCert...)
	chain = append(chain, rootPemCert...)
	tmpChainFile, err := os.CreateTemp(td, "cosign_fulcio_chain_*.cert")
	if err != nil {
		t.Fatalf("failed to create temp chain file: %v", err)
	}
	defer tmpChainFile.Close()
	if _, err := tmpChainFile.Write(chain); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}
	// Override for Fulcio root so it doesn't use TUF
	t.Setenv("SIGSTORE_ROOT_FILE", tmpChainFile.Name())

	// Create blob and write to disk
	blob := "someblob"
	blobPath := filepath.Join(td, blob)
	if err := os.WriteFile(blobPath, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}

	// Sign blob with private key
	signer, err := signature.LoadECDSASignerVerifier(leafPriv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
	if err != nil {
		t.Fatal(err)
	}

	// Create Rekor private key to sign bundle and write to disk
	rekorPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rekorSigner, err := signature.LoadECDSASignerVerifier(rekorPriv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemRekor, err := cryptoutils.MarshalPublicKeyToPEM(rekorSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	tmpRekorPubFile, err := os.CreateTemp(td, "cosign_rekor_pub_*.key")
	if err != nil {
		t.Fatalf("failed to create temp rekor pub file: %v", err)
	}
	defer tmpRekorPubFile.Close()
	if _, err := tmpRekorPubFile.Write(pemRekor); err != nil {
		t.Fatalf("failed to write rekor pub file: %v", err)
	}
	// Override for Rekor public key so it doesn't use TUF
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", tmpRekorPubFile.Name())

	// Calculate log ID, the digest of the Rekor public key
	logID, err := getLogID(rekorSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	// Create bundle with:
	// * Blob signature
	// * Signing certificate
	// * Bundle with a payload and signature over the payload
	b := cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
		Cert:            string(leafPemCert),
		Bundle: &bundle.RekorBundle{
			SignedEntryTimestamp: []byte{},
			Payload: bundle.RekorPayload{
				LogID:          logID,
				IntegratedTime: leafCert.NotBefore.Unix() + 1,
				LogIndex:       1,
				// Body is unused, certificate is fetched from b.Cert
				Body: ""},
		},
	}

	// Marshal payload, sign, and set SET in Bundle
	jsonPayload, err := json.Marshal(b.Bundle.Payload)
	if err != nil {
		t.Fatal(err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(jsonPayload)
	if err != nil {
		t.Fatal(err)
	}
	bundleSig, err := rekorSigner.SignMessage(bytes.NewReader(canonicalized))
	if err != nil {
		t.Fatal(err)
	}
	b.Bundle.SignedEntryTimestamp = bundleSig

	// Write bundle to disk
	jsonBundle, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, "bundle.sig")
	if err := os.WriteFile(bundlePath, jsonBundle, 0644); err != nil {
		t.Fatal(err)
	}

	// Verify with identity flags
	err = VerifyBlobCmd(context.Background(),
		options.KeyOpts{BundlePath: bundlePath},
		"",       /*certRef*/ // Cert is fetched from bundle
		identity, /*certEmail*/
		issuer,   /*certOidcIssuer*/
		"",       /*certChain*/ // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
		"",       /*sigRef*/    // Sig is fetched from bundle
		blobPath, /*blobRef*/
		// GitHub identity flags start
		"", "", "", "", "",
		// GitHub identity flags end
		false /*enforceSCT*/)
	if err != nil {
		t.Fatal(err)
	}

	// Failure: Invalid signature on blob results in error
	b.Bundle.SignedEntryTimestamp = []byte{}
	jsonBundle, err = json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, jsonBundle, 0644); err != nil {
		t.Fatal(err)
	}
	err = VerifyBlobCmd(context.Background(),
		options.KeyOpts{BundlePath: bundlePath},
		"",       /*certRef*/ // Cert is fetched from bundle
		identity, /*certEmail*/
		issuer,   /*certOidcIssuer*/
		"",       /*certChain*/ // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
		"",       /*sigRef*/    // Sig is fetched from bundle
		blobPath, /*blobRef*/
		// GitHub identity flags start
		"", "", "", "", "",
		// GitHub identity flags end
		false /*enforceSCT*/)
	if err == nil || !strings.Contains(err.Error(), "unable to verify SET") {
		t.Fatalf("expected error verifying SET, got %v", err)
	}
}

// getLogID calculates the digest of a PKIX-encoded public key
func getLogID(pub crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}
