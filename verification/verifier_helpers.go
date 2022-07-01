package verification

import (
	"crypto/x509"
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
	"strings"
	"time"
)

// isCriticalFailure checks whether a VerificationResult fails the entire signature verification workflow.
// signature verification workflow is considered failed if there is a VerificationResult with "Enforced" as the action but the result was inconclusive (failed to verify) or unsuccessful
func isCriticalFailure(result VerificationResult) bool {
	return result.Action == Enforced && (result.FailedToVerify || !result.Success)
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

func verifyX509TrustedIdentities(certs []*x509.Certificate, trustPolicy *TrustPolicy) error {
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
