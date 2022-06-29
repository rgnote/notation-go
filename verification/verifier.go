package verification

import (
	"context"
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
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
	policyDocument, err := loadPolicyDocument()
	if err != nil {
		return nil, err
	}
	if err = policyDocument.ValidatePolicyDocument(); err != nil {
		return nil, err
	}

	// load trust store
	x509TrustStores, err := loadX509TrustStores(policyDocument)
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
		return nil, err
	}

	if trustPolicy.SignatureVerification == "skip" {
		return getSkippedVerificationOutcome(), nil
	}

	verificationLevel, err := FindVerificationLevel(trustPolicy.SignatureVerification)
	if err != nil {
		return nil, err
	}

	artifactDigest, err := getArtifactDigestFromUri(artifactUri)
	artifactDescriptor, err := v.Repository.Resolve(ctx, artifactDigest)
	if err != nil {
		return nil, err
	}

	// get signature manifests along with signature envelopes
	sigManifests, err := v.Repository.ListSignatureManifests(ctx, artifactDescriptor.Digest)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve the signature/s from the registry. Error : %s", err)
	}
	if len(sigManifests) < 1 {
		return nil, fmt.Errorf("no signatures are associated with %q, make sure the image was successfully signed", artifactUri)
	}

	// process signature manifests
	for _, sigManifest := range sigManifests {
		// retrieve signature blob
		sigBlob, err := v.Repository.Get(ctx, sigManifest.Blob.Digest)
		if err != nil {
			return verificationOutcomes, fmt.Errorf("unable to retrieve the digital signature associated with %q from the registry, Error : %s", artifactUri, err)
		}

		verificationOutcome := v.processSignature(artifactUri, sigBlob, sigManifest, verificationLevel, trustPolicy)
		verificationOutcomes = append(verificationOutcomes, verificationOutcome)
	}

	return verificationOutcomes, nil
}

func (v *Verifier) processSignature(artifactUri string, sigBlob []byte, sigManifest registry.SignatureManifest, verificationLevel *VerificationLevel, trustPolicy *TrustPolicy) *SignatureVerificationOutcome {
	outcome := &SignatureVerificationOutcome{
		VerificationResults: []VerificationResult{},
	}

	// parse the signature envelope
	sigEnv, err := nsigner.NewSignatureEnvelopeFromBytes(sigBlob, nsigner.SignatureMediaType(sigManifest.Blob.MediaType))
	if err != nil {
		outcome.VerificationResults = append(outcome.VerificationResults, VerificationResult{
			Passed:         false,
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
	if isEndResult(verificationResult) {
		return outcome
	}

	// verify x509 authenticity
	verificationResult = v.verifyX509Authenticity(trustPolicy, signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isEndResult(verificationResult) {
		return outcome
	}

	// verify trusted identities
	verificationResult = v.verifyTrustedIdentities(trustPolicy, signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isEndResult(verificationResult) {
		return outcome
	}

	// verify expiry
	verificationResult = v.verifyExpiry(signerInfo, verificationLevel)
	outcome.VerificationResults = append(outcome.VerificationResults, verificationResult)
	if isEndResult(verificationResult) {
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
		switch _ := err.(type) {
		case nsigner.SignatureNotFoundError:
		case nsigner.MalformedSignatureError:
		case nsigner.SignatureIntegrityError:
			result = VerificationResult{
				Passed:         false,
				FailedToVerify: false,
				Error:          err,
				Type:           Integrity,
				Action:         verificationLevel.VerificationMap[Integrity],
			}
		default:
			// unexpected error
			result = VerificationResult{
				Passed:         false,
				FailedToVerify: true,
				Error:          err,
				Type:           Integrity,
				Action:         verificationLevel.VerificationMap[Integrity],
			}
		}
	} else {
		// no error means Integrity has been verified successfully
		result = VerificationResult{
			Passed:         true,
			FailedToVerify: false,
			Type:           Integrity,
			Action:         verificationLevel.VerificationMap[Integrity],
		}
	}
	return signerInfo, result
}

func (v *Verifier) verifyX509Authenticity(trustPolicy *TrustPolicy, signerInfo *nsigner.SignerInfo, verificationLevel *VerificationLevel) VerificationResult {
	// verify authenticity
	trustCerts := v.X509TrustStores[trustPolicy.TrustStore].Certificates
	_, err := nsigner.VerifyAuthenticity(signerInfo, trustCerts)
	if err != nil {
		switch _ := err.(type) {
		case nsigner.SignatureAuthenticityError:
			return VerificationResult{
				Passed:         false,
				FailedToVerify: false,
				Error:          err,
				Type:           Authenticity,
				Action:         verificationLevel.VerificationMap[Authenticity],
			}
		default:
			return VerificationResult{
				Passed:         false,
				FailedToVerify: true,
				Error:          err,
				Type:           Authenticity,
				Action:         verificationLevel.VerificationMap[Authenticity],
			}
		}

	} else {
		// no error means Integrity has been verified successfully
		return VerificationResult{
			Passed:         true,
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
			Passed:         false,
			FailedToVerify: false,
			Error:          fmt.Errorf("digital signature has expired on %q", signerInfo.SignedAttributes.Expiry),
			Type:           Expiry,
			Action:         verificationLevel.VerificationMap[Expiry],
		}
	} else {
		return VerificationResult{
			Passed:         true,
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
			Passed:         false,
			FailedToVerify: false,
			Error:          err,
			Type:           Authenticity,
			Action:         verificationLevel.VerificationMap[Authenticity],
		}
	} else {
		return VerificationResult{
			Passed:         true,
			FailedToVerify: false,
			Type:           Authenticity,
			Action:         verificationLevel.VerificationMap[Authenticity],
		}
	}
}
