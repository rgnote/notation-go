package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	nregistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signature"
	"github.com/notaryproject/notation-go/verification"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
	"time"
)

func sign(refString string) error {
	ctx := context.Background()
	ref, err := registry.ParseReference(refString)
	if err != nil {
		fmt.Println(err)
	}
	authClient := &auth.Client{
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}
	authClient.SetUserAgent("notation")
	repo := nregistry.NewRepositoryClient(authClient, ref, true)

	artifactDescriptor, err := repo.Resolve(ctx, refString)
	if err != nil {
		return err
	}

	signer, err := getSigner()
	if err != nil {
		return err
	}

	signCombinations(nsigner.SigningSchemeX509Default, signer, artifactDescriptor, repo)
	signCombinations(nsigner.SigningSchemeX509SigningAuthority, signer, artifactDescriptor, repo)
	return nil
}

func signCombinations(scheme nsigner.SigningScheme, signer notation.Signer, desc notation.Descriptor, repo *nregistry.RepositoryClient) error {
	ctx := context.Background()
	// Valid
	fmt.Println("Valid + " + scheme)
	opts := notation.SignOptions{
		Scheme:             scheme,
		SigningTime:        time.Date(2020, 11, 9, 7, 0, 0, 0, time.UTC),
		Expiry:             time.Date(2120, 11, 9, 7, 0, 0, 0, time.UTC),
		ExtendedAttributes: nil,
	}
	signature, err := signer.Sign(ctx, desc, opts)
	if err != nil {
		return err
	}
	//manifest, _, err := repo.PutSignatureManifest(ctx, signature, desc, nil)
	fmt.Println(string(signature))

	// Expired
	fmt.Println("Expired + " + scheme)
	opts = notation.SignOptions{
		Scheme:             scheme,
		SigningTime:        time.Date(2022, 7, 29, 0, 0, 0, 0, time.UTC),
		Expiry:             time.Date(2022, 7, 29, 23, 59, 0, 0, time.UTC),
		ExtendedAttributes: nil,
	}
	signature, err = signer.Sign(ctx, desc, opts)
	if err != nil {
		return err
	}
	//manifest, _, err = repo.PutSignatureManifest(ctx, signature, desc, nil)
	fmt.Println(string(signature))

	// Plugin
	fmt.Println("Plugin + " + scheme)
	opts = notation.SignOptions{
		Scheme:                    scheme,
		SigningTime:               time.Date(2020, 11, 9, 7, 0, 0, 0, time.UTC),
		Expiry:                    time.Date(2120, 11, 9, 7, 0, 0, 0, time.UTC),
		VerificationPlugin:        "plugin-name",
		VerificationPluginVersion: "1.1.1",
		ExtendedAttributes: []nsigner.Attribute{
			{
				Key:      "SomeKey",
				Critical: true,
				Value:    "SomeValue",
			},
		},
	}
	signature, err = signer.Sign(ctx, desc, opts)
	if err != nil {
		return err
	}
	//manifest, _, err = repo.PutSignatureManifest(ctx, signature, desc, nil)
	fmt.Println(string(signature))
	return nil
}

func getSigner() (notation.Signer, error) {
	rootPk, _ := rsa.GenerateKey(rand.Reader, 3072)
	root := testhelper.GetRSACertTupleWithPK(rootPk, "Notation Test Root", nil)

	leafPK, _ := rsa.GenerateKey(rand.Reader, 3072)
	leaf := testhelper.GetRSACertTupleWithPK(leafPK, "Notation Test Root", &root)

	certs := []*x509.Certificate{leaf.Cert}
	certs = append(certs, root.Cert)
	return signature.NewSigner(leaf.PrivateKey, certs)

}

func verify(refString string) error {
	ctx := context.Background()
	ref, err := registry.ParseReference(refString)
	if err != nil {
		fmt.Println(err)
	}
	authClient := &auth.Client{
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}
	authClient.SetUserAgent("notation")
	repo := nregistry.NewRepositoryClient(authClient, ref, true)

	verifier, err := verification.NewVerifier(repo)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	outcomes, err := verifier.Verify(ctx, refString)
	if err != nil {
		fmt.Println("Verification failed")
		fmt.Printf("Verification Level : %v\n", outcomes[0].VerificationLevel.Name)
		fmt.Printf("Error : %v", outcomes[0].Error)

		//for _, outcome := range outcomes {
		//	fmt.Println("Signature : " + string(outcome.SignerInfo.Signature))
		//	fmt.Println("Signature Verification Level : " + string(outcome.VerificationLevel.Name))
		//	fmt.Printf("Error : %q", outcome.Error)
		//}
	} else {
		fmt.Println("Verification succeeded")
		for i, outcome := range outcomes {
			fmt.Println("*********************************************************************")
			fmt.Printf("Signature : #%d\n", i+1)
			fmt.Println("Signature Verification Level : " + string(outcome.VerificationLevel.Name))
			for _, e := range outcome.VerificationResults {
				fmt.Println(string(e.Type)+" Success : ", e.Success)
				if !e.Success {
					fmt.Println(string(e.Type)+" failure reason : ", e.Error)
				}
			}
		}
	}
	return nil
}

func main() {
	var signSwitch bool
	signSwitch = true
	refString := "localhost:5000/net-monitor@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"
	if signSwitch {
		err := sign(refString)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := verify(refString)
		if err != nil {
			fmt.Println(err)
		}
	}
}
