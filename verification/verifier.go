package verification

import (
	"context"
	"encoding/json"
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/notaryproject/notation-go/registry"
	"time"
)

type Verifier struct {
	PolicyDocument  *PolicyDocument
	X509TrustStores map[string]*X509TrustStore
	Repository      registry.Repository
	PluginManager   *manager.Manager
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
		return nil, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("no signatures are associated with %q, make sure the image was successfully signed", artifactUri)}
	}

	// process signature manifests
	for _, sigManifest := range sigManifests {
		// retrieve signature blob
		sigBlob, err := v.Repository.Get(ctx, sigManifest.Blob.Digest)
		if err != nil {
			return verificationOutcomes, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("unable to retrieve digital signature/s associated with %q from the registry, error : %s", artifactUri, err.Error())}
		}

		verificationOutcome := v.processSignature(artifactUri, sigBlob, sigManifest, verificationLevel, trustPolicy)
		verificationOutcomes = append(verificationOutcomes, verificationOutcome)
	}

	// check whether verification succeeded or not
	for _, outcome := range verificationOutcomes {
		goodSignature := true

		// all "enforced" verifications must pass
		for _, result := range outcome.VerificationResults {
			if isFailureResult(result) {
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
			Error:          fmt.Errorf("unable to parse the digital signature associated with %q, Error : %s", artifactUri, err),
			Type:           Integrity,
			Action:         verificationLevel.VerificationMap[Integrity],
		})
		return outcome
	}

	// TODO check if the cert hashes from the signature (x5c) are present in the trust store hashes, otherwise fail early

	// verify integrity
	signerInfo, verificationResult := v.verifyIntegrity(sigEnv, verificationLevel)
	outcome.SignerInfo = signerInfo
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isFailureResult(verificationResult) {
		return outcome
	}

	// verify x509 authenticity
	verificationResult = v.verifyX509Authenticity(trustPolicy, signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isFailureResult(verificationResult) {
		return outcome
	}

	// verify trusted identities
	verificationResult = v.verifyTrustedIdentities(trustPolicy, signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isFailureResult(verificationResult) {
		return outcome
	}

	// verify expiry
	verificationResult = v.verifyExpiry(signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isFailureResult(verificationResult) {
		return outcome
	}

	// TODO verify timestamping signature if present - NOT in RC1
	// TODO verify revocation - NOT in RC1

	// invoke plugin for extended verification
	return outcome
}

func (v *Verifier) verifyIntegrity(sigEnv *nsigner.SignatureEnvelope, verificationLevel *VerificationLevel) (*nsigner.SignerInfo, VerificationResult) {
	var result VerificationResult
	signerInfo, err := sigEnv.Verify()

	if err != nil {
		switch err.(type) {
		case nsigner.SignatureNotFoundError:
		case nsigner.MalformedSignatureError:
		case nsigner.SignatureIntegrityError:
			result = VerificationResult{
				Success:        false,
				FailedToVerify: false,
				Error:          err,
				Type:           Integrity,
				Action:         verificationLevel.VerificationMap[Integrity],
			}
		default:
			// unexpected error
			result = VerificationResult{
				Success:        false,
				FailedToVerify: true,
				Error:          err,
				Type:           Integrity,
				Action:         verificationLevel.VerificationMap[Integrity],
			}
		}
	} else {
		// no error means Integrity has been verified successfully
		result = VerificationResult{
			Success:        true,
			FailedToVerify: false,
			Type:           Integrity,
			Action:         verificationLevel.VerificationMap[Integrity],
		}
	}
	return signerInfo, result
}

func (v *Verifier) verifyX509Authenticity(trustPolicy *TrustPolicy, signerInfo *nsigner.SignerInfo, verificationLevel *VerificationLevel) VerificationResult {
	// verify authenticity
	trustCerts := v.X509TrustStores[trustPolicy.TrustStores[0]].Certificates // TODO combine all trust store certs to verify authenticy
	_, err := nsigner.VerifyAuthenticity(signerInfo, trustCerts)
	if err != nil {
		switch err.(type) {
		case nsigner.SignatureAuthenticityError:
			return VerificationResult{
				Success:        false,
				FailedToVerify: false,
				Error:          err,
				Type:           Authenticity,
				Action:         verificationLevel.VerificationMap[Authenticity],
			}
		default:
			return VerificationResult{
				Success:        false,
				FailedToVerify: true,
				Error:          err,
				Type:           Authenticity,
				Action:         verificationLevel.VerificationMap[Authenticity],
			}
		}

	} else {
		// no error means Integrity has been verified successfully
		return VerificationResult{
			Success:        true,
			FailedToVerify: false,
			Type:           Authenticity,
			Action:         verificationLevel.VerificationMap[Authenticity],
		}
	}
}

func (v *Verifier) verifyExpiry(signerInfo *nsigner.SignerInfo, verificationLevel *VerificationLevel) VerificationResult {
	// verify expiry
	if !signerInfo.SignedAttributes.Expiry.IsZero() && !time.Now().Before(signerInfo.SignedAttributes.Expiry) {
		return VerificationResult{
			Success:        false,
			FailedToVerify: false,
			Error:          fmt.Errorf("digital signature has expired on %q", signerInfo.SignedAttributes.Expiry),
			Type:           Expiry,
			Action:         verificationLevel.VerificationMap[Expiry],
		}
	} else {
		return VerificationResult{
			Success:        true,
			FailedToVerify: false,
			Type:           Expiry,
			Action:         verificationLevel.VerificationMap[Expiry],
		}
	}
}

func (v *Verifier) verifyTrustedIdentities(trustPolicy *TrustPolicy, signerInfo *nsigner.SignerInfo, verificationLevel *VerificationLevel) VerificationResult {
	// verify trusted identities
	err := verifyX509TrustedIdentities(signerInfo.CertificateChain, trustPolicy)
	if err != nil {
		return VerificationResult{
			Success:        false,
			FailedToVerify: false,
			Error:          err,
			Type:           Authenticity,
			Action:         verificationLevel.VerificationMap[Authenticity],
		}
	} else {
		return VerificationResult{
			Success:        true,
			FailedToVerify: false,
			Type:           Authenticity,
			Action:         verificationLevel.VerificationMap[Authenticity],
		}
	}
}
