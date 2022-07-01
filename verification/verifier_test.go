package verification

import (
	"context"
	"fmt"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/notaryproject/notation-go/registry"
	"github.com/opencontainers/go-digest"
	"testing"
)

type mockRepository struct{}

func (t mockRepository) Resolve(ctx context.Context, reference string) (notation.Descriptor, error) {
	return notation.Descriptor{}, nil
}

func (t mockRepository) ListSignatureManifests(ctx context.Context, manifestDigest digest.Digest) ([]registry.SignatureManifest, error) {
	return nil, nil
}

func (t mockRepository) Get(ctx context.Context, digest digest.Digest) ([]byte, error) {
	return nil, nil
}

func (t mockRepository) PutSignatureManifest(ctx context.Context, signature []byte, manifest notation.Descriptor, annotaions map[string]string) (notation.Descriptor, registry.SignatureManifest, error) {
	return notation.Descriptor{}, registry.SignatureManifest{}, nil
}

type mockPluginManager struct{}

func (t mockPluginManager) Get(ctx context.Context, name string) (*manager.Plugin, error) {
	return nil, nil
}
func (t mockPluginManager) Runner(name string) (plugin.Runner, error) {
	return nil, nil
}

func TestRegistryInteractions(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	verifier := Verifier{
		PolicyDocument:  &policyDocument,
		X509TrustStores: nil,
		Repository:      mockRepository{},
		PluginManager:   mockPluginManager{},
	}

	outcomes, err := verifier.Verify(context.Background(), "uri")
	fmt.Println(outcomes)
	fmt.Println(err)
}
