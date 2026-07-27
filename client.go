package satgo

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/youmark/pkcs8"
)

type Credentials struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	RFC         string
}

type Client struct {
	credentials Credentials
	token       string
	expiresAt   time.Time
}

func newClient(cert *x509.Certificate, key *rsa.PrivateKey) *Client {
	return &Client{
		credentials: Credentials{
			Certificate: cert,
			PrivateKey:  key,
		},
	}
}

func NewClientFromPEM(certPEM, keyPEM []byte) (*Client, error) {

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	return newClient(cert, rsaKey), nil
}

func NewClientFromFiles(certPath, keyPath, password string) (*Client, error) {

	certDER, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	keyDER, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := parseCertificateDER(certDER)
	if err != nil {
		return nil, err
	}

	key, err := parsePrivateKeyDER(keyDER, password)
	if err != nil {
		return nil, err
	}

	return newClient(cert, key), nil
}

func parsePrivateKeyDER(data []byte, password string) (*rsa.PrivateKey, error) {

	key, err := pkcs8.ParsePKCS8PrivateKey(data, []byte(password))
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	return rsaKey, nil
}

func parseCertificateDER(data []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(data)
}

//func (c *Client) authenticateIfNeeded() error
