module github.com/sigstore/cosign

go 1.15

require (
	cloud.google.com/go/kms v1.2.0
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/go-openapi/runtime v0.19.27
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.14
	github.com/google/go-cmp v0.5.7
	github.com/google/go-containerregistry v0.4.1-0.20210206001656-4d068fbcb51f
	github.com/google/trillian v1.3.13
	github.com/open-policy-agent/opa v0.37.2
	github.com/peterbourgon/ff/v3 v3.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/fulcio v0.0.0-20210319080054-d000804d8115
	github.com/sigstore/rekor v0.1.1-0.20210228052401-f0b66bf3835c
	github.com/theupdateframework/go-tuf v0.0.0-20201230183259-aee6270feb55
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf
	google.golang.org/genproto v0.0.0-20220204002441-d6cc3cc0770e
	google.golang.org/protobuf v1.27.1
)
