package core

import (
	"context"
	"errors"
	"reflect"

	"github.com/eclipse-xfsc/crypto-provider-core/types"
)

/*
This function is forseen for standardize testing of RSA4096 together with providers.
*/
func Sign_Testing_Rsa4096(crypto types.CryptoProvider) bool {

	context := types.CryptoContext{
		Namespace: "transit",
		Context:   context.Background(),
	}

	err := crypto.CreateCryptoContext(context)

	if err != nil {
		return false
	}

	b := []byte{23, 55, 34}

	p := types.CryptoKeyParameter{
		Identifier: types.CryptoIdentifier{
			CryptoContext: context,
			KeyId:         "RSA4096SignKey",
		},
		KeyType: types.Rsa4096,
	}

	err = crypto.GenerateKey(p)

	if err != nil {
		return false
	}

	sig, err := crypto.Sign(p.Identifier, b)

	if err == nil {
		result, err := crypto.Verify(p.Identifier, b, sig)

		if err != nil {
			return false
		}

		err = crypto.DestroyCryptoContext(context)

		if err == nil {
			return result
		}
	}

	err = crypto.DestroyCryptoContext(context)

	if err != nil {
		return false
	}

	return false
}

/*
This function is forseen for standardize testing of ED together with providers.
*/
func Sign_Testing_Ed(crypto types.CryptoProvider) bool {

	context := types.CryptoContext{
		Namespace: "transit",
		Context:   context.Background(),
	}

	err := crypto.CreateCryptoContext(context)

	if err != nil {
		return false
	}

	b := []byte{23, 55, 34}

	p := types.CryptoKeyParameter{
		Identifier: types.CryptoIdentifier{
			CryptoContext: context,
			KeyId:         "EDKey",
		},
		KeyType: types.Ed25519,
	}

	err = crypto.GenerateKey(p)

	if err != nil {
		return false
	}

	sig, err := crypto.Sign(p.Identifier, b)

	if err == nil {
		result, err := crypto.Verify(p.Identifier, b, sig)

		if err != nil {
			return false
		}

		err = crypto.DestroyCryptoContext(context)

		if err == nil {
			return result
		}
	}

	err = crypto.DestroyCryptoContext(context)

	if err != nil {
		return false
	}

	return false
}

/*
This function is forseen for standardize testing of Aes256 together with providers.
*/
func Encryption_Testing_Aes256(crypto types.CryptoProvider) bool {
	context := types.CryptoContext{
		Namespace: "transit",
		Context:   context.Background(),
	}

	err := crypto.CreateCryptoContext(context)

	if err != nil {
		return false
	}

	b := []byte{23, 55, 34}

	p := types.CryptoKeyParameter{
		Identifier: types.CryptoIdentifier{
			CryptoContext: context,
			KeyId:         "AesKey",
		},
		KeyType: types.Aes256GCM,
	}

	err = crypto.GenerateKey(p)

	if err != nil {
		return false
	}

	ciph, err := crypto.Encrypt(p.Identifier, b)

	if reflect.DeepEqual(ciph, b) {
		return false
	}

	if err == nil {
		plain, err := crypto.Decrypt(p.Identifier, ciph)

		if err != nil {
			return false
		}

		err = crypto.DestroyCryptoContext(context)

		if err == nil {
			return reflect.DeepEqual(b, plain)
		}
	}

	err = crypto.DestroyCryptoContext(context)

	if err != nil {
		return false
	}

	return false
}

/*
This function is forseen for standardize testing together with providers.
*/
func GetKeys_Test(crypto types.CryptoProvider) (bool, error) {
	ctx := types.CryptoContext{
		Namespace: "Test",
		Group:     "2",
		Context:   context.Background(),
	}

	err := crypto.CreateCryptoContext(ctx)

	if err != nil {
		return false, err
	}

	err = crypto.GenerateKey(types.CryptoKeyParameter{
		Identifier: types.CryptoIdentifier{
			KeyId:         "key1",
			CryptoContext: ctx,
		},
		KeyType: types.Ecdsap256,
	})

	if err != nil {
		return false, err
	}

	filter := types.CryptoFilter{
		CryptoContext: ctx,
	}

	set, err := crypto.GetKeys(filter)

	if err != nil {
		return false, err
	}

	if len(set.Keys) == 1 {
		key := set.Keys[0]

		if key.Identifier.KeyId != "key1" {
			return false, errors.New("key not found")
		}

		_, err := key.GetJwk()

		if err != nil {
			return false, err
		}

		_, err = key.GetPem()

		if err != nil {
			return false, err
		}

		return true, nil
	}

	return false, err
}
