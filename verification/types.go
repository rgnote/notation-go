package verification

import (
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
	"strings"
)

// VerificationType is an enum for signature verification types such as Integrity, Authenticity, etc.
type VerificationType string

// VerificationAction is an enum for signature verification actions such as Enforced, Logged, Skipped.
type VerificationAction string

// VerificationResult encapsulates the verification result (passed or failed) for a verification type, including the
// desired verification action as specified in the trust policy
type VerificationResult struct {
	// Success is set to true if the verification was successful
	Success bool
	// Type of verification that is performed
	Type VerificationType
	// Action is the intended action for the given verification type as defined in the trust policy
	Action VerificationAction
	// Err is set if there are any errors during the verification process
	Error error
}

// SignatureVerificationOutcome encapsulates the SignerInfo (that includes the details of the digital signature)
// and results for each verification type that was performed
type SignatureVerificationOutcome struct {
	// SignerInfo contains the details of the digital signature and associated metadata
	SignerInfo *nsigner.SignerInfo
	// VerificationResults contains the verifications performed on the signature and their results
	VerificationResults []VerificationResult
	// SignedAnnotations contains arbitrary metadata relating to the target artifact that was signed
	SignedAnnotations map[string]string
}

// VerificationLevel encapsulates the signature verification preset and it's actions for each verification type
type VerificationLevel struct {
	Name            string
	VerificationMap map[VerificationType]VerificationAction
}

const (
	Integrity          VerificationType = "Integrity"
	Authenticity       VerificationType = "Authenticity"
	AuthenticTimestamp VerificationType = "AuthenticTimestamp"
	Expiry             VerificationType = "Expiry"
	Revocation         VerificationType = "Revocation"

	Enforced VerificationAction = "Enforce"
	Logged   VerificationAction = "Log"
	Skipped  VerificationAction = "Skip"
)

var (
	Strict = &VerificationLevel{
		"strict",
		map[VerificationType]VerificationAction{
			Integrity:          Enforced,
			Authenticity:       Enforced,
			AuthenticTimestamp: Enforced,
			Expiry:             Enforced,
			Revocation:         Enforced,
		},
	}

	Permissive = &VerificationLevel{
		"permissive",
		map[VerificationType]VerificationAction{
			Integrity:          Enforced,
			Authenticity:       Enforced,
			AuthenticTimestamp: Logged,
			Expiry:             Logged,
			Revocation:         Logged,
		},
	}

	Audit = &VerificationLevel{
		"audit",
		map[VerificationType]VerificationAction{
			Integrity:          Enforced,
			Authenticity:       Logged,
			AuthenticTimestamp: Logged,
			Expiry:             Logged,
			Revocation:         Logged,
		},
	}

	Skip = &VerificationLevel{
		"skip",
		map[VerificationType]VerificationAction{
			Integrity:          Skipped,
			Authenticity:       Skipped,
			AuthenticTimestamp: Skipped,
			Expiry:             Skipped,
			Revocation:         Skipped,
		},
	}

	VerificationTypes = []VerificationType{
		Integrity,
		Authenticity,
		AuthenticTimestamp,
		Expiry,
		Revocation,
	}

	VerificationActions = []VerificationAction{
		Enforced,
		Logged,
		Skipped,
	}

	VerificationLevels = []*VerificationLevel{
		Strict,
		Permissive,
		Audit,
		Skip,
	}
)

// GetVerificationLevel returns VerificationLevel struct for the given SignatureVerification struct
// throws error if SignatureVerification is invalid
func GetVerificationLevel(signatureVerification SignatureVerification) (*VerificationLevel, error) {
	var baseLevel *VerificationLevel
	for _, l := range VerificationLevels {
		if l.Name == signatureVerification.Level {
			baseLevel = l
		}
	}
	if baseLevel == nil {
		return nil, fmt.Errorf("invalid signature verification %q", signatureVerification.Level)
	}

	if len(signatureVerification.Override) == 0 {
		// nothing to override, return the base verification level
		return baseLevel, nil
	}

	if baseLevel == Skip {
		return nil, fmt.Errorf("signature verification %q can't be used to customize signature verification", baseLevel.Name)
	}

	customVerificationLevel := &VerificationLevel{
		Name:            "custom",
		VerificationMap: make(map[VerificationType]VerificationAction),
	}

	// populate the custom verification level with the base verification settings
	for k, v := range baseLevel.VerificationMap {
		customVerificationLevel.VerificationMap[k] = v
	}

	// override the verification actions with the user configured settings
	for key, value := range signatureVerification.Override {
		var verificationType VerificationType
		for _, t := range VerificationTypes {
			if strings.EqualFold(string(t), key) {
				verificationType = t
			}
		}
		if verificationType == "" {
			return nil, fmt.Errorf("verification type %q in custom signature verification is not supported", key)
		}

		var verificationAction VerificationAction
		for _, action := range VerificationActions {
			if strings.EqualFold(string(action), value) {
				verificationAction = action
			}
		}
		if verificationAction == "" {
			return nil, fmt.Errorf("verification action %q in custom signature verification is not supported", value)
		}

		if verificationType == Integrity {
			return nil, fmt.Errorf("%q verification can not be overridden in custom signature verification", key)
		} else if verificationType != Revocation && verificationAction == Skipped {
			return nil, fmt.Errorf("%q verification can not be skipped in custom signature verification", key)
		}

		customVerificationLevel.VerificationMap[verificationType] = verificationAction
	}
	return customVerificationLevel, nil
}
