module github.com/sigstore/cosign

go 1.15

require (
	cloud.google.com/go v0.102.1 // indirect
	cloud.google.com/go/kms v1.4.0
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/go-openapi/runtime v0.19.27
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.14
	github.com/google/go-cmp v0.5.8
	github.com/google/go-containerregistry v0.4.1-0.20210206001656-4d068fbcb51f
	github.com/google/trillian v1.3.13
	github.com/open-policy-agent/opa v0.27.1
	github.com/peterbourgon/ff/v3 v3.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/fulcio v0.0.0-20210319080054-d000804d8115
	github.com/sigstore/rekor v0.1.1-0.20210228052401-f0b66bf3835c
	github.com/theupdateframework/go-tuf v0.0.0-20201230183259-aee6270feb55
	golang.org/x/oauth2 v0.0.0-20220608161450-d0670ef3b1eb
	golang.org/x/sync v0.0.0-20220601150217-0de741cfad7f
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	google.golang.org/genproto v0.0.0-20220617124728-180714bec0ad
	google.golang.org/protobuf v1.28.0
)
