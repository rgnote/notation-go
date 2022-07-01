package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/notaryproject/notation-go/registry"
)

type Verifier struct {
	PolicyDocument  *PolicyDocument
	X509TrustStores map[string]*X509TrustStore
	Repository      registry.Repository
	PluginManager   pluginManager
}

// pluginManager is for mocking in unit tests
type pluginManager interface {
	Get(ctx context.Context, name string) (*manager.Plugin, error)
	Runner(name string) (plugin.Runner, error)
}

func NewVerifier(repository registry.Repository) (*Verifier, error) {
	// load trust policy
	policyDocument, err := loadPolicyDocument("") // TODO get the policy path from Dir Structure functionality
	if err != nil {
		return nil, err
	}
	if err = policyDocument.ValidatePolicyDocument(); err != nil {
		return nil, err
	}

	// load trust store
	x509TrustStores, err := loadX509TrustStores(policyDocument, "") // TODO get the trust store base path from Dir Structure functionality
	if err != nil {
		return nil, err
	}

	// load plugins
	pluginManager := manager.New("") // TODO get the plugins base path from Dir Structure functionality

	return &Verifier{
		PolicyDocument:  policyDocument,
		X509TrustStores: x509TrustStores,
		Repository:      repository,
		PluginManager:   pluginManager,
	}, nil
}

/*
Verify performs verification for each of the verification types supported in notation
See https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#signature-verification

Verify will return an array of @VerificationResult

The verification result will depend on three actions defined in the trust policy
1. Enforced - Verify method will return as soon as it finds failed verification
2. Logged - Verify method will not return for a failed verification, rather proceeds to the next verification and return the result at the end
3. Skip - Verify method will return right away without performing any verification

verification outcomes may be partial if the error is non-nil
*/
func (v *Verifier) Verify(ctx context.Context, artifactUri string) ([]*SignatureVerificationOutcome, error) {
	var verificationOutcomes []*SignatureVerificationOutcome

	trustPolicy, err := v.PolicyDocument.getApplicableTrustPolicy(artifactUri)
	if err != nil {
		return nil, ErrorNoApplicableTrustPolicy{msg: err.Error()}
	}

	if trustPolicy.SignatureVerification == "skip" {
		return nil, ErrorVerificationSkipped{msg: fmt.Sprintf("signature verification was skipped as defined in the trust policy %q", trustPolicy.Name)}
	}

	verificationLevel, _ := FindVerificationLevel(trustPolicy.SignatureVerification)

	artifactDigest, err := getArtifactDigestFromUri(artifactUri)
	artifactDescriptor, err := v.Repository.Resolve(ctx, artifactDigest)
	if err != nil {
		return nil, ErrorSignatureRetrievalFailed{msg: err.Error()}
	}

	// get signature manifests along with signature envelopes
	sigManifests, err := v.Repository.ListSignatureManifests(ctx, artifactDescriptor.Digest)
	if err != nil {
		return nil, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("unable to retrieve digital signature/s associated with %q from the registry, error : %s", artifactUri, err.Error())}
	}
	if len(sigManifests) < 1 {
		return nil, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("no signatures are associated with %q, make sure the image was signed successfully", artifactUri)}
	}

	// process signatures
	for _, sigManifest := range sigManifests {
		// retrieve signature blob
		sigBlob, err := v.Repository.Get(ctx, sigManifest.Blob.Digest)
		if err != nil {
			return verificationOutcomes, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("unable to retrieve digital signature/s associated with %q from the registry, error : %s", artifactUri, err.Error())}
		}

		verificationOutcome := v.processSignature(artifactUri, sigBlob, sigManifest, verificationLevel, trustPolicy)
		verificationOutcomes = append(verificationOutcomes, verificationOutcome)
	}

	// check whether verification has succeeded or not
	for _, outcome := range verificationOutcomes {
		goodSignature := true

		// all "enforced" verifications must pass
		for _, result := range outcome.VerificationResults {
			if isCriticalFailure(result) {
				goodSignature = false
			}
		}

		// artifact digest must match the digest from the signature payload
		if outcome.SignerInfo == nil || outcome.SignerInfo.Payload == nil {
			goodSignature = false
		}

		var payload *notation.Payload = &notation.Payload{}
		err := json.Unmarshal(outcome.SignerInfo.Payload, payload)
		if err != nil || artifactDigest != payload.TargetPayload.Digest.String() {
			goodSignature = false
		}
		outcome.SignedAnnotations = payload.TargetPayload.Annotations

		if goodSignature {
			return verificationOutcomes, nil
		}
	}

	return verificationOutcomes, ErrorVerificationFailed{}
}

func (v *Verifier) processSignature(artifactUri string, sigBlob []byte, sigManifest registry.SignatureManifest, verificationLevel *VerificationLevel, trustPolicy *TrustPolicy) *SignatureVerificationOutcome {
	outcome := &SignatureVerificationOutcome{
		VerificationResults: []VerificationResult{},
	}

	// parse the signature envelope
	sigEnv, err := nsigner.NewSignatureEnvelopeFromBytes(sigBlob, nsigner.SignatureMediaType(sigManifest.Blob.MediaType))
	if err != nil {
		outcome.VerificationResults = append(outcome.VerificationResults, VerificationResult{
			Success:        false,
			FailedToVerify: true,
			Error:          fmt.Errorf("unable to parse the digital signature associated with %q, error : %s", artifactUri, err),
			Type:           Integrity,
			Action:         verificationLevel.VerificationMap[Integrity],
		})
		return outcome
	}

	// verify integrity
	signerInfo, verificationResult := v.verifyIntegrity(sigEnv, verificationLevel)
	outcome.SignerInfo = signerInfo
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isCriticalFailure(verificationResult) {
		return outcome
	}

	err = v.defaultVerification(trustPolicy, signerInfo, verificationLevel, outcome)
	if err != nil {
		return outcome
	}

	// invoke plugin for extended verification
	return outcome
}

// defaultVerification performs verification for the default singing scheme, which is `notary.default.x509`. If there is a failure that determines the verification outcome, returns error.
func (v *Verifier) defaultVerification(trustPolicy *TrustPolicy, signerInfo *nsigner.SignerInfo, verificationLevel *VerificationLevel, outcome *SignatureVerificationOutcome) error {
	// verify x509 authenticity
	verificationResult := v.verifyX509Authenticity(trustPolicy, signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isCriticalFailure(verificationResult) {
		return errors.New("authenticity verification failed")
	}

	// verify trusted identities
	verificationResult = v.verifyTrustedIdentities(trustPolicy, signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isCriticalFailure(verificationResult) {
		return errors.New("trusted identity verification failed")
	}

	// verify expiry
	verificationResult = v.verifyExpiry(signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isCriticalFailure(verificationResult) {
		return errors.New("expiry verification failed")
	}

	// TODO verify timestamping signature if present - NOT in RC1
	// TODO verify certificate revocation - NOT in RC1
	return nil
}
