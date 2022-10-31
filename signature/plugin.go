package signature

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	notation "github.com/notaryproject/notation-go/internal"
	"github.com/notaryproject/notation-go/internal/plugin"
)

// pluginSigner signs artifacts and generates signatures.
type pluginSigner struct {
	sigProvider       provider
	envelopeMediaType string
	keyID             string
	pluginConfig      map[string]string
}

// NewSignerPlugin creates a notation.Signer that signs artifacts and generates signatures
// by delegating the one or more operations to the named plugin,
// as defined in
// https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md#signing-interfaces.
func NewSignerPlugin(runner plugin.Runner, keyID string, pluginConfig map[string]string, envelopeMediaType string) (notation.Signer, error) {
	if runner == nil {
		return nil, errors.New("nil plugin runner")
	}
	if keyID == "" {
		return nil, errors.New("nil signing keyID")
	}
	if err := ValidateEnvelopeMediaType(envelopeMediaType); err != nil {
		return nil, err
	}
	return &pluginSigner{
		sigProvider:       newExternalProvider(runner, keyID),
		envelopeMediaType: envelopeMediaType,
		keyID:             keyID,
		pluginConfig:      pluginConfig,
	}, nil
}

// Sign signs the artifact described by its descriptor and returns the marshalled envelope.
func (s *pluginSigner) Sign(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions) ([]byte, error) {
	metadata, err := s.getMetadata(ctx)
	if err != nil {
		return nil, err
	}
	if !metadata.SupportsContract(plugin.ContractVersion) {
		return nil, fmt.Errorf(
			"contract version %q is not in the list of the plugin supported versions %v",
			plugin.ContractVersion, metadata.SupportedContractVersions,
		)
	}
	if metadata.HasCapability(plugin.CapabilitySignatureGenerator) {
		return s.generateSignature(ctx, desc, opts, metadata)
	} else if metadata.HasCapability(plugin.CapabilityEnvelopeGenerator) {
		return s.generateSignatureEnvelope(ctx, desc, opts)
	}
	return nil, fmt.Errorf("plugin does not have signing capabilities")
}

func (s *pluginSigner) getMetadata(ctx context.Context) (*plugin.Metadata, error) {
	out, err := s.sigProvider.Run(ctx, new(plugin.GetMetadataRequest))
	if err != nil {
		return nil, fmt.Errorf("metadata command failed: %w", err)
	}
	metadata, ok := out.(*plugin.Metadata)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect get-plugin-metadata response type '%T'", out)
	}
	if err := metadata.Validate(); err != nil {
		return nil, fmt.Errorf("invalid plugin metadata: %w", err)
	}
	return metadata, nil
}

func (s *pluginSigner) describeKey(ctx context.Context, config map[string]string) (*plugin.DescribeKeyResponse, error) {
	req := &plugin.DescribeKeyRequest{
		ContractVersion: plugin.ContractVersion,
		KeyID:           s.keyID,
		PluginConfig:    config,
	}
	out, err := s.sigProvider.Run(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe-key command failed: %w", err)
	}
	resp, ok := out.(*plugin.DescribeKeyResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect describe-key response type '%T'", out)
	}
	return resp, nil
}

func (s *pluginSigner) generateSignature(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions, metadata *plugin.Metadata) ([]byte, error) {
	config := s.mergeConfig(opts.PluginConfig)
	// Get key info.
	key, err := s.describeKey(ctx, config)
	if err != nil {
		return nil, err
	}

	// Check keyID is honored.
	if s.keyID != key.KeyID {
		return nil, fmt.Errorf("keyID in describeKey response %q does not match request %q", key.KeyID, s.keyID)
	}

	// Generate payload to be signed.
	payload := notation.Payload{TargetArtifact: desc}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("envelope payload can't be marshaled: %w", err)
	}

	// for external plugin, pass keySpec and config before signing
	if extProvider, ok := s.sigProvider.(*externalProvider); ok {
		ks, err := plugin.ParseKeySpec(key.KeySpec)
		if err != nil {
			return nil, err
		}
		extProvider.prepareSigning(config, ks)
	}
	signingAgentId := fmt.Sprintf("%s;%s/%s", notation.SigningAgent, metadata.Name, metadata.Version)
	signReq := &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: notation.MediaTypePayloadV1,
			Content:     payloadBytes,
		},
		Signer:                   s.sigProvider,
		SigningTime:              time.Now(),
		ExtendedSignedAttributes: nil,
		SigningScheme:            signature.SigningSchemeX509,
		SigningAgent:             signingAgentId,
	}

	if !opts.Expiry.IsZero() {
		signReq.Expiry = opts.Expiry
	}

	// perform signing using pluginSigProvider
	sigEnv, err := signature.NewEnvelope(s.envelopeMediaType)
	if err != nil {
		return nil, err
	}

	sig, err := sigEnv.Sign(signReq)
	if err != nil {
		return nil, err
	}

	envContent, verErr := sigEnv.Verify()
	if verErr != nil {
		return nil, fmt.Errorf("signature returned by generateSignature cannot be verified: %v", verErr)
	}
	if err := ValidatePayloadContentType(&envContent.Payload); err != nil {
		return nil, err
	}

	// TODO: re-enable timestamping https://github.com/notaryproject/notation-go/issues/78
	return sig, nil
}

func (s *pluginSigner) mergeConfig(config map[string]string) map[string]string {
	c := make(map[string]string, len(s.pluginConfig)+len(config))
	// First clone s.PluginConfig.
	for k, v := range s.pluginConfig {
		c[k] = v
	}
	// Then set or override entries from config.
	for k, v := range config {
		c[k] = v
	}
	return c
}

func (s *pluginSigner) generateSignatureEnvelope(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions) ([]byte, error) {
	payload := notation.Payload{TargetArtifact: desc}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("envelope payload can't be marshaled: %w", err)
	}
	// Execute plugin sign command.
	req := &plugin.GenerateEnvelopeRequest{
		ContractVersion:       plugin.ContractVersion,
		KeyID:                 s.keyID,
		Payload:               payloadBytes,
		SignatureEnvelopeType: s.envelopeMediaType,
		PayloadType:           notation.MediaTypePayloadV1,
		PluginConfig:          s.mergeConfig(opts.PluginConfig),
	}
	out, err := s.sigProvider.Run(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("generate-envelope command failed: %w", err)
	}
	resp, ok := out.(*plugin.GenerateEnvelopeResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect generate-envelope response type '%T'", out)
	}

	// Check signatureEnvelopeType is honored.
	if resp.SignatureEnvelopeType != req.SignatureEnvelopeType {
		return nil, fmt.Errorf(
			"signatureEnvelopeType in generateEnvelope response %q does not match request %q",
			resp.SignatureEnvelopeType, req.SignatureEnvelopeType,
		)
	}

	sigEnv, err := signature.ParseEnvelope(s.envelopeMediaType, resp.SignatureEnvelope)
	if err != nil {
		return nil, err
	}

	envContent, err := sigEnv.Verify()
	if err != nil {
		return nil, err
	}
	if err := ValidatePayloadContentType(&envContent.Payload); err != nil {
		return nil, err
	}

	content := envContent.Payload.Content
	var signedPayload notation.Payload
	if err = json.Unmarshal(content, &signedPayload); err != nil {
		return nil, fmt.Errorf("signed envelope payload can't be unmarshaled: %w", err)
	}

	if !isPayloadDescriptorValid(content, desc, signedPayload.TargetArtifact) {
		return nil, errors.New("descriptor subject has changed")
	}

	return resp.SignatureEnvelope, nil
}

func isPayloadDescriptorValid(signedContent []byte, originalDesc, newDesc notation.Descriptor) bool {
	return originalDesc.Equal(newDesc) &&
		originalDesc.DescriptorAnnotationsPartialEqual(newDesc) &&
		!isUnknownAttributeAdded(signedContent)
}

// TODO: unit test this method: https://github.com/notaryproject/notation-go/issues/194
// isUnknownAttributeAdded checks that the unmarshalled json content does not have any unexpected keys added
func isUnknownAttributeAdded(content []byte) bool {
	var targetArtifactMap map[string]interface{}
	// Ignoring error because we already successfully unmarshalled before this point
	_ = json.Unmarshal(content, &targetArtifactMap)
	descriptor := targetArtifactMap["targetArtifact"].(map[string]interface{})

	// Explicitly remove expected keys to check if any are left over
	delete(descriptor, "mediaType")
	delete(descriptor, "digest")
	delete(descriptor, "size")
	delete(descriptor, "annotations")

	return len(targetArtifactMap) != 1 || len(descriptor) != 0
}

func parseCertChain(certChain [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(certChain))
	for i, cert := range certChain {
		cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
		certs[i] = cert
	}
	return certs, nil
}
