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

package fulcio

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed" // To enable the `go:embed` directive.
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	"golang.org/x/term"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	fulcioClient "github.com/sigstore/fulcio/pkg/generated/client"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	FlowNormal = "normal"
	FlowDevice = "device"
	FlowToken  = "token"
	altRoot    = "SIGSTORE_ROOT_FILE"
)

// This is the root in the fulcio project.
//go:embed fulcio.pem
var rootPem string

var fulcioTargetStr = `fulcio.crt.pem`

type oidcConnector interface {
	OIDConnect(string, string, string) (*oauthflow.OIDCIDToken, error)
}

type realConnector struct {
	flow oauthflow.TokenGetter
}

func (rf *realConnector) OIDConnect(url, clientID, secret string) (*oauthflow.OIDCIDToken, error) {
	return oauthflow.OIDConnect(url, clientID, secret, rf.flow)
}

type signingCertProvider interface {
	SigningCert(params *operations.SigningCertParams, authInfo runtime.ClientAuthInfoWriter, opts ...operations.ClientOption) (*operations.SigningCertCreated, error)
}

func getCertForOauthID(priv *ecdsa.PrivateKey, scp signingCertProvider, connector oidcConnector, oidcIssuer string, oidcClientID string) (certPem, chainPem []byte, err error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	tok, err := connector.OIDConnect(oidcIssuer, oidcClientID, "")
	if err != nil {
		return nil, nil, err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, nil, err
	}

	bearerAuth := httptransport.BearerToken(tok.RawString)

	content := strfmt.Base64(pubBytes)
	signedChallenge := strfmt.Base64(proof)
	params := operations.NewSigningCertParams()
	params.SetCertificateRequest(
		&models.CertificateRequest{
			PublicKey: &models.CertificateRequestPublicKey{
				Algorithm: models.CertificateRequestPublicKeyAlgorithmEcdsa,
				Content:   &content,
			},
			SignedEmailAddress: &signedChallenge,
		},
	)

	resp, err := scp.SigningCert(params, bearerAuth)
	if err != nil {
		return nil, nil, err
	}

	// split the cert and the chain
	certBlock, chainPem := pem.Decode([]byte(resp.Payload))
	certPem = pem.EncodeToMemory(certBlock)
	return certPem, chainPem, nil
}

// GetCert returns the PEM-encoded signature of the OIDC identity returned as part of an interactive oauth2 flow plus the PEM-encoded cert chain.
func GetCert(ctx context.Context, priv *ecdsa.PrivateKey, idToken, flow, oidcIssuer, oidcClientID string, fClient *fulcioClient.Fulcio) (certPemBytes, chainPemBytes []byte, err error) {
	c := &realConnector{}
	switch flow {
	case FlowDevice:
		c.flow = oauthflow.NewDeviceFlowTokenGetter(
			oidcIssuer, oauthflow.SigstoreDeviceURL, oauthflow.SigstoreTokenURL)
	case FlowNormal:
		c.flow = oauthflow.DefaultIDTokenGetter
	case FlowToken:
		c.flow = &oauthflow.StaticTokenGetter{RawToken: idToken}
	default:
		return nil, nil, fmt.Errorf("unsupported oauth flow: %s", flow)
	}

	return getCertForOauthID(priv, fClient.Operations, c, oidcIssuer, oidcClientID)
}

type Signer struct {
	Cert  []byte
	Chain []byte
	pub   *ecdsa.PublicKey
	*signature.ECDSASignerVerifier
}

func NewSigner(ctx context.Context, idToken, oidcIssuer, oidcClientID string, fClient *fulcioClient.Fulcio) (*Signer, error) {
	priv, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "generating cert")
	}
	signer, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	var flow string
	switch {
	case idToken != "":
		flow = FlowToken
	case !term.IsTerminal(0):
		fmt.Fprintln(os.Stderr, "Non-interactive mode detected, using device flow.")
		flow = FlowDevice
	default:
		flow = FlowNormal
	}
	cert, chain, err := GetCert(ctx, priv, idToken, flow, oidcIssuer, oidcClientID, fClient) // TODO, use the chain.
	if err != nil {
		return nil, errors.Wrap(err, "retrieving cert")
	}
	f := &Signer{
		pub:                 &priv.PublicKey,
		ECDSASignerVerifier: signer,
		Cert:                cert,
		Chain:               chain,
	}
	return f, nil

}

func (f *Signer) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return &f.pub, nil
}

var _ signature.Signer = &Signer{}

var Roots *x509.CertPool

func init() {
	cp := x509.NewCertPool()
	rootEnv := os.Getenv(altRoot)
	if rootEnv != "" {
		raw, err := ioutil.ReadFile(rootEnv)
		if err != nil {
			panic(fmt.Sprintf("error reading root PEM file: %s", err))
		}
		if !cp.AppendCertsFromPEM(raw) {
			panic("error creating root cert pool")
		}
	} else {
		// First try retrieving from TUF root. Requires running `cosign init`
		// Otherwise use rootPem.
		ctx := context.Background()
		buf := tuf.ByteDestination{Buffer: &bytes.Buffer{}}
		err := tuf.GetTarget(ctx, fulcioTargetStr, &buf)
		if err != nil {
			if !cp.AppendCertsFromPEM([]byte(rootPem)) {
				panic("error creating root cert pool")
			}
		} else {
			// TODO: Remove this when re-signing the next Fulcio certificate.
			replaced := strings.ReplaceAll(buf.String(), "\n  ", "\n")
			if !cp.AppendCertsFromPEM([]byte(replaced)) {
				panic("error creating root cert pool")
			}
		}
	}
	Roots = cp
}
