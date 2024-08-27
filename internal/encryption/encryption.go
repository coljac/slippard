package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// EncryptWithSSHKey encrypts data using the provided user's SSH public key
func EncryptWithSSHKey(data string, keyPath string) (string, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPubKey := &privateKey.PublicKey

	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, []byte(data))
	if err != nil {
		return "", err
	}

	return string(encryptedBytes), nil
}

// DecryptWithSSHKey decrypts data using the provided user's SSH private key
func DecryptWithSSHKey(encryptedData []byte, keyPath string) (string, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedData)
	if err != nil {
		return "", err
	}

	return string(decryptedBytes), nil
}
