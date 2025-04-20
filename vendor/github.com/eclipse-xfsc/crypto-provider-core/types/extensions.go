package types

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func (key CryptoKey) GetPem() (p *pem.Block, err error) {
	if !strings.Contains(string(key.KeyType), "aes") {

		block, _ := pem.Decode(key.Key)
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block")
		}

		return block, nil

	}
	return nil, errors.New("Unsupported")
}

func (key CryptoKey) GetJwk() (jwk.Key, error) {
	var pemData = key.Key
	block, rest := pem.Decode(pemData)

	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	var err error
	var j jwk.Key
	if len(rest) > 0 {
		j, err = jwk.ParseKey(pemData, jwk.WithPEM(true))

		if err != nil {
			return nil, err
		}

		var certs []*x509.Certificate
		crt, err := x509.ParseCertificate(block.Bytes)
		certs = append(certs, crt)

		if err != nil {
			return nil, err
		}

		for {
			var block *pem.Block
			block, pemData = pem.Decode(pemData)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" {
				fmt.Println("Skipping non-certificate PEM block")
				continue
			}

			crt, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("Error parsing certificate:", err)
				return nil, err
			}

			certs = append(certs, crt)
		}

		chain := new(cert.Chain)
		j.Set(jwk.X509CertChainKey, chain)
		for _, c := range certs {
			j.X509CertChain().AddString(base64.StdEncoding.EncodeToString(c.Raw))
		}

	} else {
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)

		if err != nil {
			return nil, err
		}

		j, err = jwk.FromRaw(pubKey)

		if err != nil {
			return nil, err
		}
	}

	err = j.Set("kid", key.Identifier.KeyId)

	return j, err
}
