// Copyright 2021 The Rekor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/pkg/cosign/fulcio"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kms"
)

type annotationsMap struct {
	annotations map[string]string
}

func (a *annotationsMap) Set(s string) error {
	if a.annotations == nil {
		a.annotations = map[string]string{}
	}
	kvp := strings.SplitN(s, "=", 2)
	if len(kvp) != 2 {
		return fmt.Errorf("invalid flag: %s, expected key=value", s)
	}

	a.annotations[kvp[0]] = kvp[1]
	return nil
}

func (a *annotationsMap) String() string {
	s := []string{}
	for k, v := range a.annotations {
		s = append(s, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(s, ",")
}

func Sign() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign sign", flag.ExitOnError)
		key         = flagset.String("key", "", "path to the private key")
		kmsVal      = flagset.String("kms", "", "sign via a private key stored in a KMS")
		upload      = flagset.Bool("upload", true, "whether to upload the signature")
		payloadPath = flagset.String("payload", "", "path to a payload file to use rather than generating one.")
		force       = flagset.Bool("f", false, "skip warnings and confirmations")
		annotations = annotationsMap{}
	)
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "cosign sign -key <key> [-payload <path>] [-a key=value] [-upload=true|false] [-f] <image uri>",
		ShortHelp:  `Sign the supplied container image.`,
		LongHelp: `Sign the supplied container image.

EXAMPLES
  # sign a container image with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign sign <IMAGE>

  # sign a container image with a local key pair file
  cosign sign -key cosign.pub <IMAGE>

  # sign a container image and add annotations
  cosign sign -key cosign.pub -a key1=value1 -a key2=value2 <IMAGE>

  # sign a container image with a key pair stored in Google Cloud KMS
  cosign sign -kms gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> <IMAGE>`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			// A key file (or kms address) is required unless we're in experimental mode!
			if !cosign.Experimental() {
				if *key == "" && *kmsVal == "" {
					return &KeyParseError{}
				}
			}
			if len(args) != 1 {
				return flag.ErrHelp
			}

			return SignCmd(ctx, *key, args[0], *upload, *payloadPath, annotations.annotations, *kmsVal, GetPass, *force)
		},
	}
}

func SignCmd(ctx context.Context, keyPath string,
	imageRef string, upload bool, payloadPath string,
	annotations map[string]string, kmsVal string, pf cosign.PassFunc, force bool) error {

	if keyPath != "" && kmsVal != "" {
		return &KeyParseError{}
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}
	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return errors.Wrap(err, "getting remote image")
	}
	// The payload can be specified via a flag to skip generation.
	var payload []byte
	if payloadPath != "" {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = ioutil.ReadFile(filepath.Clean(payloadPath))
	} else {
		payload, err = cosign.Payload(get.Descriptor, annotations)
	}
	if err != nil {
		return errors.Wrap(err, "payload")
	}

	var signature []byte
	var pemBytes []byte
	var cert, chain string
	switch {
	case kmsVal != "":
		k, err := kms.Get(ctx, kmsVal)
		if err != nil {
			return err
		}
		signature, err = k.Sign(ctx, payload)
		if err != nil {
			return errors.Wrap(err, "signing")
		}
		publicKey, err := k.PublicKey(ctx)
		if err != nil {
			return errors.Wrap(err, "getting public key")
		}
		pemBytes = cosign.KeyToPem(publicKey)
	case keyPath != "":
		var pub *ecdsa.PublicKey
		signature, pub, err = sign(ctx, keyPath, payload, pf)
		if err != nil {
			return errors.Wrap(err, "signing payload")
		}
		pemBytes = cosign.KeyToPem(pub)
	default: // Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		priv, err := cosign.GeneratePrivateKey()
		if err != nil {
			return errors.Wrap(err, "generating cert")
		}
		fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")
		cert, chain, err = fulcio.GetCert(ctx, priv) // TODO, use the chain.
		if err != nil {
			return errors.Wrap(err, "retrieving cert")
		}
		h := sha256.Sum256(payload)
		signature, err = ecdsa.SignASN1(rand.Reader, priv, h[:])
		if err != nil {
			return errors.Wrap(err, "signing")
		}
		pemBytes = []byte(cert)
	}

	if !upload {
		fmt.Println(base64.StdEncoding.EncodeToString(signature))
		return nil
	}

	// sha256:... -> sha256-...
	dstTag, err := cosign.DestinationTag(ref, get)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Pushing signature to:", dstTag.String())

	if err := cosign.Upload(signature, payload, dstTag, string(cert), string(chain)); err != nil {
		return err
	}

	if !cosign.Experimental() {
		return nil
	}

	// Check if the image is public (no auth in Get)
	if !force {
		if _, err := remote.Get(ref); err != nil {
			fmt.Print("warning: uploading to the public transparency log for a private image, please confirm [Y/N]: ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				return err
			}
			if response != "Y" {
				fmt.Println("not uploading to transparency log")
				return nil
			}
		}
	}
	index, err := cosign.UploadTLog(signature, payload, pemBytes)
	if err != nil {
		return err
	}
	fmt.Println("tlog entry created with index: ", index)
	return nil
}

func sign(ctx context.Context, keyPath string, payload []byte, pf cosign.PassFunc) (signature []byte, publicKey *ecdsa.PublicKey, err error) {
	kb, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return
	}
	pass, err := pf(false)
	if err != nil {
		return
	}
	pk, err := cosign.LoadPrivateKey(kb, pass)
	if err != nil {
		return
	}
	publicKey = &pk.PublicKey

	h := sha256.Sum256(payload)
	signature, err = ecdsa.SignASN1(rand.Reader, pk, h[:])
	if err != nil {
		return
	}
	return
}