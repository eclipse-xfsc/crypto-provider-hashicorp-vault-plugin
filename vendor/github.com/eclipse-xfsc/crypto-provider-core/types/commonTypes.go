package types

import "slices"

type HashAlgorithm string
type KeyType string
type CryptoLogLevel string

const (
	Sha2224 HashAlgorithm = "sha2-224"
	Sha2256 HashAlgorithm = "sha2-256"
	Sha2384 HashAlgorithm = "sha2-384"
	Sha2512 HashAlgorithm = "sha2-512"
	Sha3224 HashAlgorithm = "sha3-224"
	Sha3256 HashAlgorithm = "sha3-256"
	Sha3384 HashAlgorithm = "sha3-384"
	Sha3512 HashAlgorithm = "sha3-512"
)

func ValidateHashFunction(HashAlgorithm HashAlgorithm) bool {
	return slices.Contains[[]string, string]([]string{"sha2-224", "sha2-256", "sha2-384", "sha2-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"}, string(HashAlgorithm))
}

const (
	Aes256GCM KeyType = "aes256-gcm96"
	Ed25519   KeyType = "ed25519"
	Ecdsap256 KeyType = "ecdsa-p256"
	Ecdsap384 KeyType = "ecdsa-p384"
	Ecdsap512 KeyType = "ecdsa-p512"
	Rsa2048   KeyType = "rsa-2048"
	Rsa3072   KeyType = "rsa-3072"
	Rsa4096   KeyType = "rsa-4096"
	KeyValue  KeyType = "keyValue"
)

const (
	DEBUG CryptoLogLevel = "DEBUG"
	INFO  CryptoLogLevel = "INFO"
	FATAL CryptoLogLevel = "FATAL"
	LOG   CryptoLogLevel = "LOG"
)

func ValidateMethod(KeyType KeyType) bool {
	return slices.Contains[[]string, string]([]string{"aes256-gcm96", "ed25519", "ecdsa-p256","ecdsa-p384","ecdsa-p512","rsa-2048","rsa-3072", "rsa-4096"}, string(KeyType))
}
