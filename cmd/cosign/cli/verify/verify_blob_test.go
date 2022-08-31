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
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/swag"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/internal/pkg/cosign/rekor/mock"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/test"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
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
	td := t.TempDir()

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
		time.Now(), leafPriv, rootCert, rootPriv)
	expiredLeafCert, _ := test.GenerateLeafCertWithExpiration(identity, issuer,
		time.Now().Add(-time.Hour), leafPriv, rootCert, rootPriv)

	// Make rekor signer
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
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", tmpRekorPubFile.Name())

	var makeSignature = func(blob []byte) string {
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}
		return string(sig)
	}
	blobBytes := []byte("foo")
	blobSignature := makeSignature(blobBytes)

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
			signature:    blobSignature,
			sigVerifier:  signer,
			experimental: false,
			shouldErr:    false,
		},
		{
			name:         "valid signature with public key - experimental",
			blob:         blobBytes,
			signature:    blobSignature,
			sigVerifier:  signer,
			experimental: true,
			rekorEntry:   nil,
			shouldErr:    false,
		},
		{
			name:         "valid signature with public key - good bundle provided",
			blob:         blobBytes,
			signature:    blobSignature,
			sigVerifier:  signer,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredLeafCert, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with public key - bad bundle SET",
			blob:         blobBytes,
			signature:    blobSignature,
			sigVerifier:  signer,
			experimental: false,
			bundlePath: makeLocalBundle(t, *signer, blobBytes, []byte(blobSignature),
				unexpiredLeafCert, true),
			shouldErr: true,
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
			signature:    blobSignature,
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
			name:         "valid signature with unexpired certificate - experimental",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         unexpiredLeafCert,
			sigVerifier:  signer,
			experimental: true,
			rekorEntry: makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredLeafCert, true),
			shouldErr: false,
		},

		{
			name:         "valid signature with unexpired certificate - experimental & rekor entry found",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         unexpiredLeafCert,
			experimental: true,
			rekorEntry: makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredLeafCert, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			sigVerifier:  signer,
			experimental: false,
			shouldErr:    true,
		},

		{
			name:         "valid signature with expired certificate - experimental good rekor lookup",
			blob:         blobBytes,
			signature:    blobSignature,
			sigVerifier:  signer,
			cert:         expiredLeafCert,
			experimental: true,
			rekorEntry: makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafCert, true),
			shouldErr: false,
		},

		{
			name:         "valid signature with expired certificate - experimental bad rekor integrated time",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			sigVerifier:  signer,
			experimental: true,
			rekorEntry: makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafCert, false),
			shouldErr: true,
		},

		{
			name:         "valid signature with unexpired certificate - good bundle, nonexperimental",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         unexpiredLeafCert,
			sigVerifier:  signer,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredLeafCert, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate - good bundle, nonexperimental",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			sigVerifier:  signer,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafCert, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate - bundle with bad expiration",
			blob:         blobBytes,
			signature:    blobSignature,
			sigVerifier:  signer,
			cert:         expiredLeafCert,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafCert, false),
			shouldErr: true,
		},
		{
			name:         "valid signature with expired certificate - bundle with bad SET",
			blob:         blobBytes,
			signature:    blobSignature,
			sigVerifier:  signer,
			cert:         expiredLeafCert,
			experimental: false,
			bundlePath: makeLocalBundle(t, *signer, blobBytes, []byte(blobSignature),
				expiredLeafCert, true),
			shouldErr: true,
		},
		{
			name:         "valid signature with expired certificate - experimental good bundle",
			blob:         blobBytes,
			signature:    blobSignature,
			sigVerifier:  signer,
			cert:         expiredLeafCert,
			experimental: true,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafCert, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate - experimental bad rekor entry",
			blob:         blobBytes,
			signature:    blobSignature,
			sigVerifier:  signer,
			cert:         expiredLeafCert,
			experimental: true,
			// This is the wrong signer for the SET!
			rekorEntry: makeRekorEntry(t, *signer, blobBytes, []byte(blobSignature),
				expiredLeafCert, true),
			shouldErr: true,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			var mClient client.Rekor
			mClient.Entries = &mock.EntriesClient{Entries: tt.rekorEntry}
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

func makeRekorEntry(t *testing.T, rekorSigner signature.ECDSASignerVerifier,
	pyld []byte, sig []byte, signingCert *x509.Certificate, expiryValid bool) *models.LogEntry {
	ctx := context.Background()
	// Calculate log ID, the digest of the Rekor public key
	logID, err := getLogID(rekorSigner.Public())
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord.V001Entry{}
	h := sha256.Sum256(pyld)
	signingCertPem, _ := cryptoutils.MarshalCertificateToPEM(signingCert)
	pe, err := hashedrekord.CreateFromArtifactProperties(ctx, types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(h[:]),
		SignatureBytes: sig,
		PublicKeyBytes: signingCertPem,
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.NewEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var integratedTime time.Time
	if expiryValid {
		integratedTime = signingCert.NotAfter.Add(-time.Second)
	} else {
		integratedTime = signingCert.NotAfter.Add(time.Second)
	}
	e := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(0),
		LogID:          swag.String(logID),
	}
	// Marshal payload, sign, and set SET in Bundle
	jsonPayload, err := json.Marshal(e)
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
	uuid, _ := cosign.ComputeLeafHash(&e)

	e.Verification = &models.LogEntryAnonVerification{
		SignedEntryTimestamp: bundleSig,
		InclusionProof: &models.InclusionProof{
			LogIndex: swag.Int64(0),
			TreeSize: swag.Int64(1),
			RootHash: swag.String(hex.EncodeToString(uuid)),
			Hashes:   []string{},
		},
	}
	return &models.LogEntry{hex.EncodeToString(uuid): e}
}

func makeLocalBundle(t *testing.T, rekorSigner signature.ECDSASignerVerifier,
	pyld []byte, sig []byte, signingCert *x509.Certificate, expiryValid bool) string {
	td := t.TempDir()

	signingCertPem, _ := cryptoutils.MarshalCertificateToPEM(signingCert)
	// Create bundle.
	entry := makeRekorEntry(t, rekorSigner, pyld, sig, signingCert, expiryValid)
	var e models.LogEntryAnon
	for _, v := range *entry {
		e = v
	}
	b := cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
		Cert:            string(signingCertPem),
		Bundle: &bundle.RekorBundle{
			Payload: bundle.RekorPayload{
				Body:           e.Body,
				IntegratedTime: *e.IntegratedTime,
				LogIndex:       *e.LogIndex,
				LogID:          *e.LogID,
			},
			SignedEntryTimestamp: e.Verification.SignedEntryTimestamp,
		},
	}

	// Write bundle to disk
	jsonBundle, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, "bundle.sig")
	if err := os.WriteFile(bundlePath, jsonBundle, 0644); err != nil {
		t.Fatal(err)
	}
	return bundlePath
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
