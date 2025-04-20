package types

import (
	"context"
	"encoding/json"
	"regexp"
)

type CryptoLogger interface {
	Log(level CryptoLogLevel, msg string, err error)
}

type CryptoContext struct {
	Namespace string
	Group     string
	Context   context.Context
	Logger    CryptoLogger
	Engine    string
}

type CryptoIdentifier struct {
	KeyId         string
	CryptoContext CryptoContext
}

type CryptoFilter struct {
	Filter        regexp.Regexp
	CryptoContext CryptoContext
}

type CryptoKeyParameter struct {
	Identifier CryptoIdentifier
	KeyType    KeyType
	Params     json.RawMessage
}

type CryptoHashParameter struct {
	Identifier    CryptoIdentifier
	HashAlgorithm HashAlgorithm
}

type CryptoKey struct {
	Key     []byte //pem format expected in case of key pair
	Version string
	CryptoKeyParameter
}

type CryptoKeySet struct {
	Keys []CryptoKey
}

type CryptoProviderModule interface {
	GetCryptoProvider() CryptoProvider
}

type CryptoContextError struct {
	Err error
}

func (e *CryptoContextError) Error() string {
	return e.Err.Error()
}

/*
Crypto Provider Interface Behavior:

1. Crypto Context must be created before use of any function. Funcs must return CryptoContext Error, when Context not initialized.
2. Crypto Context should be destroyed when Context is not more required.
*/
type CryptoProvider interface {
	/*
		Crypto Context Creation Methods. Create the context before any other method.
	*/
	CreateCryptoContext(context CryptoContext) error
	DestroyCryptoContext(context CryptoContext) error
	IsCryptoContextExisting(context CryptoContext) (bool, error)

	/*
		Methods which are just working with created Crypto Context. Ensure that the existing context is checked before execute operations.
	*/
	GetNamespaces(context CryptoContext) ([]string, error)
	GenerateRandom(context CryptoContext, number int) ([]byte, error)
	Hash(parameter CryptoHashParameter, msg []byte) ([]byte, error)
	Encrypt(parameter CryptoIdentifier, data []byte) ([]byte, error)
	Decrypt(parameter CryptoIdentifier, data []byte) ([]byte, error)
	Sign(parameter CryptoIdentifier, data []byte) ([]byte, error)
	GetKeys(parameter CryptoFilter) (*CryptoKeySet, error)
	GetKey(parameter CryptoIdentifier) (*CryptoKey, error)
	Verify(parameter CryptoIdentifier, data []byte, signature []byte) (bool, error)
	GenerateKey(parameter CryptoKeyParameter) error
	IsKeyExisting(parameter CryptoIdentifier) (bool, error)
	DeleteKey(parameter CryptoIdentifier) error
	RotateKey(parameter CryptoIdentifier) error
	GetSupportedKeysAlgs() []KeyType
	GetSupportedHashAlgs() []HashAlgorithm
}
