package main

import (
	"errors"
	"os"

	"github.com/eclipse-xfsc/crypto-provider-core/v2/types"
	"github.com/eclipse-xfsc/crypto-provider-hashicorp-vault-plugin/v2/vault"
	"github.com/sirupsen/logrus"
)

type VaultCryptoProvider struct {
}

func main() {
	addr := os.Getenv("CRYPTO_PROVIDER_HASHICORP_VAULT_ADDRESS")
	if addr == "" {
		addr = "0.0.0.0:50051"
	}
	logrus.Info("CRYPTO_PROVIDER_HASHICORP_VAULT ADDR: " + addr)
	impl := new(VaultCryptoProvider)
	err, stop := types.Start(impl, addr)

	defer stop()

	if err != nil {
		logrus.Error(err)
	}
}

func convertToCryptoKey(desc vault.VaultKeyDescription, identifier types.CryptoIdentifier) types.CryptoKey {
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

func (l VaultCryptoProvider) CreateCryptoContext(context types.CryptoContext) error {
	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		Context:    context.Context,
		EnginePath: buildEnginePath(context),
		Engine:     context.Engine,
	}

	return vault.VaultCreateCryptoContext(v)
}

func (l VaultCryptoProvider) DestroyCryptoContext(context types.CryptoContext) error {
	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		Context:    context.Context,
		EnginePath: buildEnginePath(context),
		Engine:     context.Engine,
	}

	return vault.VaultDestroyCryptoContext(v)
}

func (l VaultCryptoProvider) IsCryptoContextExisting(context types.CryptoContext) (bool, error) {
	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		Context:    context.Context,
		EnginePath: buildEnginePath(context),
		Engine:     context.Engine,
	}

	return vault.VaultEngineExists(v), nil
}

func (l VaultCryptoProvider) GetNamespaces(context types.CryptoContext) ([]string, error) {
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

	return vault.VaultGetNamespaces(v)
}

func (l VaultCryptoProvider) GetKey(parameter types.CryptoIdentifier) (*types.CryptoKey, error) {
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

	if err == nil && len(key) > 0 {
		desc := key[0]
		k := convertToCryptoKey(desc, parameter)
		return &k, nil
	}

	if err == nil && len(key) == 0 {
		return nil, errors.New("no key found")
	}

	return nil, errors.ErrUnsupported
}

func (l VaultCryptoProvider) GetKeys(parameter types.CryptoFilter) (*types.CryptoKeySet, error) {
	keys := make([]types.CryptoKey, 0)

	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		EnginePath: buildEnginePath(parameter.CryptoContext),
		Context:    parameter.CryptoContext.Context,
		Engine:     parameter.CryptoContext.Engine,
	}

	list, err := vault.VaultListKeys(v, parameter.Filter)

	if err != nil {
		return nil, err
	}

	for _, key := range list {
		p := types.CryptoIdentifier{
			CryptoContext: parameter.CryptoContext,
			KeyId:         key,
		}

		k, err := l.GetKey(p)
		if err != nil {
			return nil, err
		}

		keys = append(keys, *k)
	}
	return &types.CryptoKeySet{Keys: keys}, nil
}

func (l VaultCryptoProvider) GenerateRandom(context types.CryptoContext, number int) ([]byte, error) {
	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		EnginePath: buildEnginePath(context),
	}

	return vault.VaultGenerateRandom(v, number)
}

func (l VaultCryptoProvider) Hash(parameter types.CryptoHashParameter, msg []byte) ([]byte, error) {
	v := vault.VaultParameter{
		Client:     vault.VaultGetClient(),
		Context:    parameter.Identifier.CryptoContext.Context,
		EnginePath: buildEnginePath(parameter.Identifier.CryptoContext),
	}
	return vault.VaultHashData(v, parameter.HashAlgorithm, msg)
}
func (l VaultCryptoProvider) Encrypt(parameter types.CryptoIdentifier, data []byte) ([]byte, error) {
	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    parameter.CryptoContext.Context,
			EnginePath: buildEnginePath(parameter.CryptoContext),
		},
		KeyName: parameter.KeyId,
	}

	return vault.VaultEncrypt(v, data)
}
func (l VaultCryptoProvider) Decrypt(parameter types.CryptoIdentifier, data []byte) ([]byte, error) {
	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    parameter.CryptoContext.Context,
			EnginePath: buildEnginePath(parameter.CryptoContext),
		},
		KeyName: parameter.KeyId,
	}

	return vault.VaultDecrypt(v, data)
}
func (l VaultCryptoProvider) Sign(parameter types.CryptoIdentifier, data []byte) ([]byte, error) {
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

	d, err := vault.VaultSignData(v, data)

	return d, err
}
func (l VaultCryptoProvider) Verify(parameter types.CryptoIdentifier, data []byte, signature []byte) (bool, error) {
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

	return vault.VaultVerifyData(v, data, signature)
}

func (l VaultCryptoProvider) GenerateKey(parameter types.CryptoKeyParameter) error {
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

	return vault.VaultCreateKey(v)
}

func (l VaultCryptoProvider) DeleteKey(identifier types.CryptoIdentifier) error {
	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    identifier.CryptoContext.Context,
			EnginePath: buildEnginePath(identifier.CryptoContext),
			Engine:     identifier.CryptoContext.Engine,
		},
		KeyName: identifier.KeyId,
	}

	return vault.VaultDeleteKey(v)
}

func (l VaultCryptoProvider) RotateKey(identifier types.CryptoIdentifier) error {
	v := vault.VaultKeyParameter{
		Vault: vault.VaultParameter{
			Client:     vault.VaultGetClient(),
			Context:    identifier.CryptoContext.Context,
			EnginePath: buildEnginePath(identifier.CryptoContext),
		},
		KeyName: identifier.KeyId,
	}

	return vault.VaultRotateKey(v)
}

func (l VaultCryptoProvider) IsKeyExisting(identifier types.CryptoIdentifier) (bool, error) {
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
		return false, err
	}

	if keys == nil {
		return false, nil
	}

	if keys != nil {
		return len(keys) > 0, nil
	}

	return false, nil
}

func (l VaultCryptoProvider) GetSupportedHashAlgs() []types.HashAlgorithm {
	return []types.HashAlgorithm{types.Sha2224, types.Sha2256, types.Sha2384}
}

func (l VaultCryptoProvider) GetSupportedKeysAlgs() []types.KeyType {
	return []types.KeyType{types.Ecdsap256, types.Ecdsap384, types.Ecdsap512, types.Aes256GCM, types.Ed25519, types.Rsa2048, types.Rsa3072, types.Rsa4096}
}
