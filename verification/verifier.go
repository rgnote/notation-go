package verification

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	"os"
	"strings"
	"time"
)

type Verifier struct {
	PolicyDocument  *PolicyDocument
	X509TrustStores map[string][]*X509TrustStore
	Repository      registry.SignatureRepository
}

func NewVerifier(repository registry.SignatureRepository) (*Verifier, err) {
	policyDocument, err := loadPolicyDocument()
	if err != nil {
		return nil, err
	}
	map[string][]*X509TrustStore, err := loadX509TrustStores()
	return &Verifier{
		PolicyDocument:  policyDocument,
		X509TrustStores: x509TrustStores,
		Repository:      repository,
	}, nil
}

func loadPolicyDocument() (*PolicyDocument, error){
	policyDocumentPath := "" // TODO get the policy path

	var policyDocument *PolicyDocument
	jsonFile, err := os.Open(policyDocumentPath)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, err
	}
	return policyDocument, nil
}

func loadX509TrustStores()

/*
Verify performs verification for each of the verification types supported in notation
See https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#signature-verification

Verify will return an array of @VerificationResult

The verification result will depend on three actions defined in the trust policy
1. Enforced - Verify method will return as soon as it finds failed verification
2. Logged - Verify method will not return for a failed verification, rather proceeds to the next verification and return the result at the end
3. Skip - Verify method will return right away without performing any verification
*/
func (v *Verifier) Verify(artifactUri string) ([]VerificationResult, error) {
	var ctx context.Context

	var verificationResults []VerificationResult
	trustPolicy, err := v.PolicyDocument.getApplicableTrustPolicy(artifactUri)
	if err != nil {
		return nil, err
	}

	if trustPolicy.SignatureVerification == "skip" {
		return getSkippedVerificationResults(), nil
	}

	verificationLevel, err := FindVerificationLevel(trustPolicy.SignatureVerification)
	fmt.Println(verificationLevel)
	if err != nil {
		return nil, err
	}

	artifactDigest, err := getArtifactDigestFromUri(artifactUri)
	fmt.Println(artifactDigest)

	// get signature manifests along with signature envelopes
	// sigManifests, err := v.Repository.ListSignatureManifests(ctx, artifactDigest)
	// if err != nil {
	//	return nil, fmt.Errorf("unable to retrieve the signature/s from the registry. Error : %s", err)
	//}

	var sigManifests []notation.Descriptor

	// return error if no signature manifests
	if len(sigManifests) < 1 {
		return nil, fmt.Errorf("no signatures are associated with %q, make sure the image was signed", artifactUri)
	}

	for _, sigManifest := range sigManifests {
		sigBlob, err := v.Repository.Get(sigManifest.Blob.Digest)
		if err != nil {
			return nil, fmt.Errorf("unabled to retrieve the signature associated with %q from the registry, Error : %s", artifactUri, err)
		}
		sigEnv, err := SignatureEnvelope.NewSignatureEnvelopeFromBytes(sigBlob, sigManifest.Blob.MediaType)
		verificationResult := processSignature(sigEnv, verificationLevel, trustPolicy)
		verificationResults = append(verificationResults, verificationResult)
	}

	// No error
	return verificationResults, nil
}

func (v *Verifier) processSignature(sigEnv SignatureEnvelope, verificationLevel VerificationLevel, trustPolicy *TrustPolicy) []VerificationResult {
	var results []VerificationResult
	// TODO check the root cert hash is present in trust store hashes, otherwise fail early

	// verify integrity and authenticity
	trustCerts := v.getTrustCerts(trustPolicy)
	anchoredCert, signerInfo, err := sigEnv.Verify(trustCerts)
	if err != nil {
		switch v := err.(type) {
		case nsigner.SignatureIntegrityError:
			results = append(results, VerificationResult{
				Error: err,
				Type:  Integrity,
			})
			if verificationLevel.VerificationMap[Integrity] == Enforced {
				return results
			}
			// handle integrity error
		case nsigner.SignatureAuthenticityError:
			results = append(results, VerificationResult{
				Error: err,
				Type:  Authenticity,
			})
			if verificationLevel.VerificationMap[Authenticity] == Enforced {
				return results
			}
		default:
			results = append(results, VerificationResult{
				FailedToVerify: true,
				Error:          err,
				Type:           Integrity,
			})
			if verificationLevel.VerificationMap[Integrity] == Enforced {
				return results
			}
		}
	}

	// trusted identities
	err = verifyX509TrustedIdentities(signerInfo.CertificateChain, trustPolicy)
	if err != nil {
		results = append(results, VerificationResult{
			Passed: false,
			Error:  err,
			Type:   Authenticity,
		})
		if verificationLevel.VerificationMap[Authenticity] == Enforced {
			return results
		}
	}

	// verify expiry time of the signature is in the future
	if signerInfo.SignedAttributes.Expiry != nil && !time.Now().Before(signerInfo.SignedAttributes.Expiry) {
		results = append(results, VerificationResult{
			Passed: false,
			Error:  fmt.Errorf("digital signature has expired on %q", signerInfo.SignedAttributes.Expiry),
			Type:   Expiry,
		})
		if verificationLevel.VerificationMap[Expiry] == Enforced {
			return results
		}
	}

	// TODO verify timestamping signature if present - NOT in RC1
	// TODO verify revocation - NOT in RC1
	// invoke plugin for extended verification
}

func (v *Verifier) getTrustCerts(policy *TrustPolicy) []*x509.Certificate {
	return nil
}

func getSkippedVerificationResults() (results []VerificationResult) {
	for _, t := range VerificationTypes {
		results = append(results, VerificationResult{
			Type:   t,
			Action: Skipped,
		})
	}
}

func verifyX509TrustedIdentities(certs []*x509.Certificate, trustPolicy TrustPolicy) error {
	if isPresent(wildcard, trustPolicy.TrustedIdentities) {
		return nil
	}

	var trustedX509Identities []map[string]string
	for _, identity := range trustPolicy.TrustedIdentities {
		i := strings.Index(identity, ":")

		identityPrefix := identity[:i]
		identityValue := identity[i+1:]

		if identityPrefix == x509Subject {
			parsedSubject, err := parseDistinguishedName(identityValue)
			if err != nil {
				return err
			}
			trustedX509Identities = append(trustedX509Identities, parsedSubject)
		}
	}

	if len(trustedX509Identities) == 0 {
		return nil
	}

	leafCert := certs[0]

	leafCertDN, err := parseDistinguishedName(leafCert.Subject.String()) // parse the certificate subject following rfc 4514 DN syntax
	if err != nil {
		return fmt.Errorf("error while parsing the certificate subject from the digital signature. Error : %q", err)
	}
	for _, trustedX509Identity := range trustedX509Identities {
		if isSubsetDN(trustedX509Identity, leafCertDN) {
			return nil
		}
	}

	return fmt.Errorf("signing certificate from the digital signature does not match the X.509 trusted identities %q defined in the trust policy %q", trustedX509Identities, trustPolicy.Name)
}
