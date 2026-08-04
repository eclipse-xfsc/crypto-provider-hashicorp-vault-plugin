package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/eclipse-xfsc/crypto-provider-core/v2/types"
	"github.com/eclipse-xfsc/crypto-provider-hashicorp-vault-plugin/v2/vault"
	"github.com/sirupsen/logrus"
)

type VaultCryptoProvider struct{}

func init() {
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)

	if os.Getenv("LOG_LEVEL") == "debug" {
		logrus.SetLevel(logrus.DebugLevel)
	}
}

func main() {
	addr := os.Getenv("CRYPTO_PROVIDER_HASHICORP_VAULT_ADDRESS")
	if addr == "" {
		addr = "0.0.0.0:50051"
	}

	logrus.WithFields(logrus.Fields{
		"address":  addr,
		"logLevel": logrus.GetLevel().String(),
	}).Info("Starting HashiCorp Vault crypto provider")

	impl := new(VaultCryptoProvider)

	err, stop := types.Start(impl, addr)
	if stop != nil {
		defer stop()
	}

	if err != nil {
		logrus.WithError(err).Error("Failed starting crypto provider")
		return
	}

	logrus.Info("Crypto provider stopped")
}

func contextFields(context types.CryptoContext) logrus.Fields {
	return logrus.Fields{
		"namespace":  context.Namespace,
		"group":      context.Group,
		"context":    context.Context,
		"engine":     fmt.Sprintf("%v", context.Engine),
		"enginePath": buildEnginePath(context),
	}
}

func identifierFields(identifier types.CryptoIdentifier) logrus.Fields {
	fields := contextFields(identifier.CryptoContext)
	fields["keyId"] = identifier.KeyId
	return fields
}

func keyTypeFields(keyType types.KeyType) logrus.Fields {
	return logrus.Fields{
		"keyType":       fmt.Sprintf("%v", keyType),
		"keyTypeQuoted": fmt.Sprintf("%q", keyType),
		"keyTypeGoType": fmt.Sprintf("%T", keyType),
	}
}

func mergeFields(fieldSets ...logrus.Fields) logrus.Fields {
	result := logrus.Fields{}

	for _, fields := range fieldSets {
		for key, value := range fields {
			result[key] = value
		}
	}

	return result
}

func convertToCryptoKey(
	desc vault.VaultKeyDescription,
	identifier types.CryptoIdentifier,
) types.CryptoKey {
	logrus.WithFields(mergeFields(
		identifierFields(identifier),
		logrus.Fields{
			"version": desc.Version,
			"type":    fmt.Sprintf("%v", desc.Type),
		},
	)).Debug("Converting Vault key description")

	return types.CryptoKey{
		Key:     []byte(desc.Key),
		Version: desc.Version,
		CryptoKeyParameter: types.CryptoKeyParameter{
			Identifier: identifier,
			KeyType:    desc.Type,
			Params:     desc.Params,
		},
	}
}

func buildEnginePath(context types.CryptoContext) string {
	if context.Group == "" {
		return context.Namespace
	}

	return context.Namespace + "/" + context.Group
}

func (l VaultCryptoProvider) CreateCryptoContext(
	context types.CryptoContext,
) error {
	logger := logrus.WithFields(contextFields(context))
	logger.Info("Creating crypto context")

	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		Context:    context.Context,
		EnginePath: buildEnginePath(context),
		Engine:     context.Engine,
	}

	if err := vault.VaultCreateCryptoContext(v); err != nil {
		logger.WithError(err).Error("Failed creating crypto context")
		return err
	}

	logger.Info("Crypto context created")
	return nil
}

func (l VaultCryptoProvider) DestroyCryptoContext(
	context types.CryptoContext,
) error {
	logger := logrus.WithFields(contextFields(context))
	logger.Info("Destroying crypto context")

	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		Context:    context.Context,
		EnginePath: buildEnginePath(context),
		Engine:     context.Engine,
	}

	if err := vault.VaultDestroyCryptoContext(v); err != nil {
		logger.WithError(err).Error("Failed destroying crypto context")
		return err
	}

	logger.Info("Crypto context destroyed")
	return nil
}

func (l VaultCryptoProvider) IsCryptoContextExisting(
	context types.CryptoContext,
) (bool, error) {
	logger := logrus.WithFields(contextFields(context))
	logger.Debug("Checking whether crypto context exists")

	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		Context:    context.Context,
		EnginePath: buildEnginePath(context),
		Engine:     context.Engine,
	}

	exists := vault.VaultEngineExists(v)

	logger.WithField("exists", exists).
		Debug("Finished checking crypto context")

	return exists, nil
}

func (l VaultCryptoProvider) GetNamespaces(
	context types.CryptoContext,
) ([]string, error) {
	logger := logrus.WithFields(contextFields(context))
	logger.Debug("Getting namespaces")

	v := vault.VaultParameter{
		Client:  vault.VaultGetClient(),
		Context: context.Context,
		Engine:  context.Engine,
	}

	namespace := ""
	if context.Namespace != "" {
		namespace = context.Namespace
	}

	if context.Group != "" {
		namespace = namespace + "/" + context.Group
	}

	if namespace != "" {
		v.EnginePath = namespace
	}

	namespaces, err := vault.VaultGetNamespaces(v)
	if err != nil {
		logger.WithError(err).Error("Failed getting namespaces")
		return nil, err
	}

	logger.WithField("count", len(namespaces)).
		Debug("Namespaces retrieved")

	return namespaces, nil
}

func (l VaultCryptoProvider) GetKey(
	parameter types.CryptoIdentifier,
) (*types.CryptoKey, error) {
	logger := logrus.WithFields(identifierFields(parameter))
	logger.Debug("Getting key")

	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    parameter.CryptoContext.Context,
			EnginePath: buildEnginePath(parameter.CryptoContext),
			Engine:     parameter.CryptoContext.Engine,
		},
		KeyName: parameter.KeyId,
	}

	key, err := vault.VaultGetKey(v)
	if err != nil {
		logger.WithError(err).Error("Failed getting key")
		return nil, err
	}

	if len(key) == 0 {
		err := errors.New("no key found")
		logger.WithError(err).Warn("Key not found")
		return nil, err
	}

	desc := key[0]

	logger.WithFields(logrus.Fields{
		"version": desc.Version,
		"keyType": fmt.Sprintf("%v", desc.Type),
	}).Debug("Key retrieved")

	result := convertToCryptoKey(desc, parameter)
	return &result, nil
}

func (l VaultCryptoProvider) GetKeys(
	parameter types.CryptoFilter,
) (*types.CryptoKeySet, error) {
	logger := logrus.WithFields(contextFields(parameter.CryptoContext))
	logger.Debug("Listing keys")

	keys := make([]types.CryptoKey, 0)

	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		EnginePath: buildEnginePath(parameter.CryptoContext),
		Context:    parameter.CryptoContext.Context,
		Engine:     parameter.CryptoContext.Engine,
	}

	list, err := vault.VaultListKeys(v, parameter.Filter)
	if err != nil {
		logger.WithError(err).Error("Failed listing keys")
		return nil, err
	}

	logger.WithField("count", len(list)).
		Debug("Key names retrieved")

	for _, key := range list {
		keyLogger := logger.WithField("keyId", key)

		p := types.CryptoIdentifier{
			CryptoContext: parameter.CryptoContext,
			KeyId:         key,
		}

		k, err := l.GetKey(p)
		if err != nil {
			keyLogger.WithError(err).Error("Failed retrieving listed key")
			return nil, err
		}

		keys = append(keys, *k)
	}

	logger.WithField("count", len(keys)).
		Debug("Keys retrieved")

	return &types.CryptoKeySet{Keys: keys}, nil
}

func (l VaultCryptoProvider) GenerateRandom(
	context types.CryptoContext,
	number int,
) ([]byte, error) {
	logger := logrus.WithFields(mergeFields(
		contextFields(context),
		logrus.Fields{
			"number": number,
		},
	))

	logger.Debug("Generating random bytes")

	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		EnginePath: buildEnginePath(context),
	}

	result, err := vault.VaultGenerateRandom(v, number)
	if err != nil {
		logger.WithError(err).Error("Failed generating random bytes")
		return nil, err
	}

	logger.WithField("resultLength", len(result)).
		Debug("Random bytes generated")

	return result, nil
}

func (l VaultCryptoProvider) Hash(
	parameter types.CryptoHashParameter,
	msg []byte,
) ([]byte, error) {
	logger := logrus.WithFields(mergeFields(
		identifierFields(parameter.Identifier),
		logrus.Fields{
			"hashAlgorithm": fmt.Sprintf("%v", parameter.HashAlgorithm),
			"messageLength": len(msg),
		},
	))

	logger.Debug("Hashing data")

	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		Context:    parameter.Identifier.CryptoContext.Context,
		EnginePath: buildEnginePath(parameter.Identifier.CryptoContext),
	}

	result, err := vault.VaultHashData(v, parameter.HashAlgorithm, msg)
	if err != nil {
		logger.WithError(err).Error("Failed hashing data")
		return nil, err
	}

	logger.WithField("hashLength", len(result)).
		Debug("Data hashed")

	return result, nil
}

func (l VaultCryptoProvider) Encrypt(
	parameter types.CryptoIdentifier,
	data []byte,
) ([]byte, error) {
	logger := logrus.WithFields(mergeFields(
		identifierFields(parameter),
		logrus.Fields{
			"dataLength": len(data),
		},
	))

	logger.Debug("Encrypting data")

	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    parameter.CryptoContext.Context,
			EnginePath: buildEnginePath(parameter.CryptoContext),
		},
		KeyName: parameter.KeyId,
	}

	result, err := vault.VaultEncrypt(v, data)
	if err != nil {
		logger.WithError(err).Error("Failed encrypting data")
		return nil, err
	}

	logger.WithField("resultLength", len(result)).
		Debug("Data encrypted")

	return result, nil
}

func (l VaultCryptoProvider) Decrypt(
	parameter types.CryptoIdentifier,
	data []byte,
) ([]byte, error) {
	logger := logrus.WithFields(mergeFields(
		identifierFields(parameter),
		logrus.Fields{
			"dataLength": len(data),
		},
	))

	logger.Debug("Decrypting data")

	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    parameter.CryptoContext.Context,
			EnginePath: buildEnginePath(parameter.CryptoContext),
		},
		KeyName: parameter.KeyId,
	}

	result, err := vault.VaultDecrypt(v, data)
	if err != nil {
		logger.WithError(err).Error("Failed decrypting data")
		return nil, err
	}

	logger.WithField("resultLength", len(result)).
		Debug("Data decrypted")

	return result, nil
}

func (l VaultCryptoProvider) Sign(
	parameter types.CryptoIdentifier,
	data []byte,
) ([]byte, error) {
	logger := logrus.WithFields(mergeFields(
		identifierFields(parameter),
		logrus.Fields{
			"dataLength": len(data),
		},
	))

	logger.Debug("Signing data")

	v := vault.VaultHashParameter{
		KeyParameter: vault.VaultKeyParameter{
			KeyName: parameter.KeyId,
			Vault: vault.VaultParameter{
				Client:     vault.VaultGetClient(),
				Context:    parameter.CryptoContext.Context,
				EnginePath: buildEnginePath(parameter.CryptoContext),
			},
		},
		HashAlgorithm: "default",
	}

	result, err := vault.VaultSignData(v, data)
	if err != nil {
		logger.WithError(err).Error("Failed signing data")
		return nil, err
	}

	logger.WithField("signatureLength", len(result)).
		Debug("Data signed")

	return result, nil
}

func (l VaultCryptoProvider) Verify(
	parameter types.CryptoIdentifier,
	data []byte,
	signature []byte,
) (bool, error) {
	logger := logrus.WithFields(mergeFields(
		identifierFields(parameter),
		logrus.Fields{
			"dataLength":      len(data),
			"signatureLength": len(signature),
		},
	))

	logger.Debug("Verifying signature")

	valid, err := vault.VaultVerifyData(
		vault.VaultHashParameter{
			KeyParameter: vault.VaultKeyParameter{
				KeyName: parameter.KeyId,
				Vault: vault.VaultParameter{
					Client:     vault.VaultGetClient(),
					Context:    parameter.CryptoContext.Context,
					EnginePath: buildEnginePath(parameter.CryptoContext),
				},
			},
			HashAlgorithm: "default",
		},
		data,
		signature,
	)

	if err != nil {
		logger.WithError(err).Error("Failed verifying signature")
		return false, err
	}

	logger.WithField("valid", valid).
		Debug("Signature verification completed")

	return valid, nil
}

func (l VaultCryptoProvider) GenerateKey(
	parameter types.CryptoKeyParameter,
) error {
	logger := logrus.WithFields(mergeFields(
		identifierFields(parameter.Identifier),
		keyTypeFields(parameter.KeyType),
		logrus.Fields{
			"paramsPresent": parameter.Params != nil,
		},
	))

	logger.Info("Generating crypto key")

	// This log is intentionally verbose to identify invalid enum/string
	// conversions such as the control character \u0003.
	logger.WithFields(logrus.Fields{
		"keyTypeValue":      fmt.Sprintf("%v", parameter.KeyType),
		"keyTypeQuoted":     fmt.Sprintf("%q", parameter.KeyType),
		"keyTypeGoSyntax":   fmt.Sprintf("%#v", parameter.KeyType),
		"keyTypeUnderlying": fmt.Sprintf("%T", parameter.KeyType),
	}).Info("Received crypto key type")

	v := vault.VaultKeyTypeParameter{
		KeyParameter: vault.VaultKeyParameter{
			KeyName: parameter.Identifier.KeyId,
			Vault: vault.VaultParameter{
				Client:     vault.VaultGetClient(),
				Context:    parameter.Identifier.CryptoContext.Context,
				EnginePath: buildEnginePath(parameter.Identifier.CryptoContext),
				Engine:     parameter.Identifier.CryptoContext.Engine,
			},
			Params: parameter.Params,
		},
		KeyType: parameter.KeyType,
	}

	logger.WithFields(logrus.Fields{
		"vaultKeyType":       fmt.Sprintf("%v", v.KeyType),
		"vaultKeyTypeQuoted": fmt.Sprintf("%q", v.KeyType),
		"vaultKeyTypeType":   fmt.Sprintf("%T", v.KeyType),
		"vaultEnginePath":    v.KeyParameter.Vault.EnginePath,
		"vaultEngine":        fmt.Sprintf("%v", v.KeyParameter.Vault.Engine),
	}).Info("Calling VaultCreateKey")

	if err := vault.VaultCreateKey(v); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			"vaultKeyType":       fmt.Sprintf("%v", v.KeyType),
			"vaultKeyTypeQuoted": fmt.Sprintf("%q", v.KeyType),
		}).Error("Failed generating crypto key")

		return err
	}

	logger.Info("Crypto key generated")
	return nil
}

func (l VaultCryptoProvider) DeleteKey(
	identifier types.CryptoIdentifier,
) error {
	logger := logrus.WithFields(identifierFields(identifier))
	logger.Info("Deleting key")

	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    identifier.CryptoContext.Context,
			EnginePath: buildEnginePath(identifier.CryptoContext),
			Engine:     identifier.CryptoContext.Engine,
		},
		KeyName: identifier.KeyId,
	}

	if err := vault.VaultDeleteKey(v); err != nil {
		logger.WithError(err).Error("Failed deleting key")
		return err
	}

	logger.Info("Key deleted")
	return nil
}

func (l VaultCryptoProvider) RotateKey(
	identifier types.CryptoIdentifier,
) error {
	logger := logrus.WithFields(identifierFields(identifier))
	logger.Info("Rotating key")

	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    identifier.CryptoContext.Context,
			EnginePath: buildEnginePath(identifier.CryptoContext),
		},
		KeyName: identifier.KeyId,
	}

	if err := vault.VaultRotateKey(v); err != nil {
		logger.WithError(err).Error("Failed rotating key")
		return err
	}

	logger.Info("Key rotated")
	return nil
}

func (l VaultCryptoProvider) IsKeyExisting(
	identifier types.CryptoIdentifier,
) (bool, error) {
	logger := logrus.WithFields(identifierFields(identifier))
	logger.Debug("Checking whether key exists")

	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    identifier.CryptoContext.Context,
			EnginePath: buildEnginePath(identifier.CryptoContext),
			Engine:     identifier.CryptoContext.Engine,
		},
		KeyName: identifier.KeyId,
	}

	keys, err := vault.VaultGetKey(v)
	if err != nil {
		logger.WithError(err).Error("Failed checking whether key exists")
		return false, err
	}

	exists := len(keys) > 0

	logger.WithFields(logrus.Fields{
		"exists": exists,
		"count":  len(keys),
	}).Debug("Finished checking whether key exists")

	return exists, nil
}

func (l VaultCryptoProvider) GetSupportedHashAlgs() []types.HashAlgorithm {
	algorithms := []types.HashAlgorithm{
		types.Sha2224,
		types.Sha2256,
		types.Sha2384,
	}

	logrus.WithField("algorithms", fmt.Sprintf("%v", algorithms)).
		Debug("Returning supported hash algorithms")

	return algorithms
}

func (l VaultCryptoProvider) GetSupportedKeysAlgs() []types.KeyType {
	algorithms := []types.KeyType{
		types.Ecdsap256,
		types.Ecdsap384,
		types.Ecdsap512,
		types.Aes256GCM,
		types.Ed25519,
		types.Rsa2048,
		types.Rsa3072,
		types.Rsa4096,
	}

	for index, algorithm := range algorithms {
		logrus.WithFields(logrus.Fields{
			"index":         index,
			"keyType":       fmt.Sprintf("%v", algorithm),
			"keyTypeQuoted": fmt.Sprintf("%q", algorithm),
			"keyTypeGoType": fmt.Sprintf("%T", algorithm),
		}).Debug("Supported key algorithm")
	}

	return algorithms
}
