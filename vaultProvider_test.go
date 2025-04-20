package main

import (
	"testing"

	core "github.com/eclipse-xfsc/crypto-provider-core"
	"github.com/eclipse-xfsc/crypto-provider-core/types"
	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigFile(".env")
	viper.ReadInConfig()
	viper.AutomaticEnv()
}

func Test_signing_rsa4096(t *testing.T) {
	vaultProvider := new(VaultCryptoProvider)

	if !core.Sign_Testing_Rsa4096(vaultProvider) {
		t.Error()
	}
}

func Test_encryption_aes256(t *testing.T) {
	vaultProvider := new(VaultCryptoProvider)
	if !core.Encryption_Testing_Aes256(vaultProvider) {
		t.Error()
	}
}

func Test_encryption_ed(t *testing.T) {
	localProvider := new(VaultCryptoProvider)
	if !core.Sign_Testing_Ed(localProvider) {
		t.Error()
	}
}

func Test_GetKeys(t *testing.T) {
	localProvider := new(VaultCryptoProvider)
	b, err := core.GetKeys_Test(localProvider)

	if !b {
		t.Error(err)
	}
}

func Test_GetKey(t *testing.T) {
	localProvider := new(VaultCryptoProvider)

	cryptoContext := types.CryptoContext{
		Namespace: "transit",
		Group:     "",
	}

	err := localProvider.CreateCryptoContext(cryptoContext)

	if err != nil {
		t.Error()
	}

	err = localProvider.GenerateKey(types.CryptoKeyParameter{
		Identifier: types.CryptoIdentifier{
			KeyId:         "eckey",
			CryptoContext: cryptoContext,
		},
		KeyType: types.Ecdsap256,
	})

	if err != nil {
		t.Error()
	}

	key, err := localProvider.GetKey(types.CryptoIdentifier{
		KeyId:         "eckey",
		CryptoContext: cryptoContext,
	})

	if err != nil {
		t.Error()
	}

	if key == nil {
		t.Error()
	}
}
