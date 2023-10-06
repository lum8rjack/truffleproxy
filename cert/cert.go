/*
Copyright © 2023 @lum8rjack
*/
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	outdir string
)

const (
	filename string = "truffleproxy"
)

// CertCmd represents the cert command
var CertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Create a new private key and certificate file",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		start()
	},
}

func init() {
	CertCmd.Flags().StringVarP(&outdir, "out", "o", ".", "Output directory to save the private key and certificate file (default current directory)")
}

func start() {
	if outdir != "" {
		if _, err := os.Stat(outdir); os.IsNotExist(err) {
			log.Fatal(err)
		}
	}

	outdir = fmt.Sprintf("%s/%s", outdir, filename)

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Fill in certificate details
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "truffleproxy"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate a certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Write the private key to a file
	keyname := fmt.Sprintf("%s.key", outdir)
	keyFile, err := os.Create(keyname)
	if err != nil {
		log.Fatal(err)
	}
	defer keyFile.Close()

	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	if _, err := keyFile.Write(keyBytes); err != nil {
		log.Fatal(err)
	}
	log.Printf("Successfully wrote private key: %s\n", keyname)

	// Write the certificate to a file
	certname := fmt.Sprintf("%s.crt", outdir)
	certFile, err := os.Create(certname)
	if err != nil {
		panic(err)
	}
	defer certFile.Close()

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	if _, err := certFile.Write(certBytes); err != nil {
		log.Fatal(err)
	}
	log.Printf("Successfully wrote certificate file: %s\n", certname)
}
