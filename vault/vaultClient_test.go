package vault

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"testing"

	"github.com/eclipse-xfsc/crypto-provider-core/types"
)

func getemptyNamespaces(engine string) ([]string, error) {
	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		Context:    context.Background(),
		EnginePath: "fffffff",
		Engine:     engine,
	}
	return VaultGetNamespaces(v)
}

func getNamespaces(engine string) ([]string, error) {
	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		Context:    context.Background(),
		EnginePath: "testest",
		Engine:     engine,
	}

	err := VaultCreateEngine(v)

	if err != nil {
		return nil, err
	}

	spaces, err := VaultGetNamespaces(v)

	if err != nil {
		return nil, err
	}

	err = VaultDeleteEngine(v)

	return spaces, err
}

func TestGetNamespaces(t *testing.T) {

	spaces, err := getNamespaces(Transit)

	if err != nil {
		t.Fail()
	}

	if len(spaces) == 0 {
		t.Fail()
	}
}

func TestGetNamespacesKV(t *testing.T) {

	spaces, err := getNamespaces(KV)

	if err != nil {
		t.Fail()
	}

	if len(spaces) == 0 {
		t.Fail()
	}
}

func TestGetEmptyTransitNamespaces(t *testing.T) {
	spaces, err := getemptyNamespaces(Transit)

	if err != nil {
		t.Fail()
	}

	if len(spaces) > 0 {
		t.Fail()
	}
}

func TestGetEmptyKVNamespaces(t *testing.T) {

	spaces, err := getemptyNamespaces(KV)

	if err != nil {
		t.Fail()
	}

	if len(spaces) > 0 {
		t.Fail()
	}
}

func testKeyCreation(v VaultParameter, t *testing.T, expectCryptoException bool, keyType types.KeyType, params map[string]interface{}) (*VaultKeyTypeParameter, error) {

	p, err := json.Marshal(params)

	if err != nil {
		return nil, errors.New("fail")
	}

	key := VaultKeyTypeParameter{
		KeyParameter: VaultKeyParameter{
			KeyName: "Test" + string(keyType),
			Vault:   v,
			Params:  p,
		},
		KeyType: keyType,
	}

	err = VaultCreateKey(key)

	if err != nil {

		if expectCryptoException {
			_, ok := err.(*types.CryptoContextError)
			if ok {
				return nil, errors.New("fail")
			}
		}
		return nil, errors.New("fail")
	}

	spaces, err := VaultGetNamespaces(v)

	if err != nil {
		return nil, errors.New("fail")
	}

	if len(spaces) == 0 {
		return nil, errors.New("fail")
	}

	if spaces[0] != v.EnginePath {
		return nil, errors.New("fail")
	}
	return &key, nil
}

func TestGetNameSpaceWithKeyCreationAndCryptoContextCreation(t *testing.T) {

	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		EnginePath: "test",
		Engine:     Transit,
	}

	err := VaultCreateCryptoContext(v)
	if err != nil {
		t.Fail()
		return
	}

	testKeyCreation(v, t, false, types.Rsa2048, make(map[string]interface{}))

	err = VaultDestroyCryptoContext(v)

	if err != nil {
		t.Fail()
	}
}

func TestGetNamespacesWithKeyCreation(t *testing.T) {
	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		EnginePath: "test",
	}
	testKeyCreation(v, t, true, types.Aes256GCM, make(map[string]interface{}))
}

func TestGetKey(t *testing.T) {
	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		EnginePath: "test",
		Engine:     Transit,
	}

	err := VaultCreateCryptoContext(v)

	if err != nil {
		t.Fail()
	}

	key, err := testKeyCreation(v, t, false, types.Ed25519, make(map[string]interface{}))

	if err != nil {
		t.Fail()
	}

	desc, err := VaultGetKey(key.KeyParameter)

	if err != nil {
		t.Fail()
	}

	if len(desc) == 0 {
		t.Fail()
	}

	key, err = testKeyCreation(v, t, false, types.Aes256GCM, make(map[string]interface{}))

	if err != nil {
		t.Fail()
	}

	desc, err = VaultGetKey(key.KeyParameter)

	if err != nil {
		t.Fail()
	}

	if len(desc) == 0 {
		t.Fail()
	}
}

func TestVaultErrors(t *testing.T) {
	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		EnginePath: "test",
		Engine:     KV,
	}

	err := VaultCreateCryptoContext(v)
	if err != nil {
		t.Fail()
		return
	}

	vkp := VaultKeyParameter{
		KeyName: "x",
		Vault:   v,
	}

	_, err = VaultEncrypt(vkp, []byte{0})

	if err.Error() != engineError {
		t.Fail()
	}

	_, err = VaultEncrypt(vkp, []byte{0})

	if err.Error() != engineError {
		t.Fail()
	}

	_, err = VaultHashData(v, types.Sha2224, []byte{0})

	if err.Error() != engineError {
		t.Fail()
	}

	_, err = VaultGenerateRandom(v, 0)

	if err.Error() != engineError {
		t.Fail()
	}

	vhp := VaultHashParameter{
		KeyParameter:  vkp,
		HashAlgorithm: types.Sha2224,
	}

	_, err = VaultSignData(vhp, []byte{0})

	if err.Error() != engineError {
		t.Fail()
	}

	_, err = VaultVerifyData(vhp, []byte{0}, []byte{0})

	if err.Error() != engineError {
		t.Fail()
	}

	err = VaultDeleteEngine(v)
	if err != nil {
		t.Fail()
		return
	}
}

func TestCreateKVKey(t *testing.T) {

	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		EnginePath: "test",
		Engine:     KV,
	}

	err := VaultCreateCryptoContext(v)
	if err != nil {
		t.Fail()
		return
	}

	data := make(map[string]interface{})
	data["test"] = "44444"

	kp, err := testKeyCreation(v, t, false, types.KeyValue, data)

	if err != nil {
		t.Fail()
	}

	desc, err := VaultGetKey(kp.KeyParameter)

	if err != nil {
		t.Fail()
	}

	if len(desc) == 0 {
		t.Fail()
	}

	err = VaultDeleteKey(kp.KeyParameter)

	if err != nil {
		t.Fail()
	}

	desc, err = VaultGetKey(kp.KeyParameter)

	if err != nil || len(desc) > 0 {
		t.Fail()
	}

	err = VaultDestroyCryptoContext(v)

	if err != nil {
		t.Fail()
	}

}

func TestCreateKeyWithWrongTypeAndTransit(t *testing.T) {

	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		EnginePath: "test",
		Engine:     Transit,
	}

	err := VaultCreateCryptoContext(v)
	if err != nil {
		t.Fail()
		return
	}

	data := make(map[string]interface{})
	data["test"] = "44444"

	kp, err := testKeyCreation(v, t, false, types.KeyValue, data)

	if err == nil {
		t.Fail()
	}

	if kp != nil {
		t.Fail()
	}

	err = VaultDestroyCryptoContext(v)

	if err != nil {
		t.Fail()
	}
}

func TestListKeys(t *testing.T) {

	client := VaultGetClient()
	v := VaultParameter{
		Client:     client,
		EnginePath: "test",
		Engine:     KV,
	}

	v2 := VaultParameter{
		Client:     client,
		EnginePath: "test2",
		Engine:     Transit,
	}

	err := VaultCreateCryptoContext(v)
	if err != nil {
		t.Fail()
		return
	}

	err = VaultCreateCryptoContext(v2)
	if err != nil {
		t.Fail()
		return
	}

	list0, err := VaultListKeys(v2, regexp.Regexp{})

	if len(list0) != 0 {
		t.Fail()
	}

	if err != nil {
		t.Fail()
		return
	}

	data := make(map[string]interface{})
	data["test"] = "44444"
	data["xy"] = "12222"

	_, err = testKeyCreation(v, t, false, types.KeyValue, data)

	if err != nil {
		t.Fail()
	}

	_, err = testKeyCreation(v2, t, false, types.Rsa2048, data)

	if err != nil {
		t.Fail()
	}

	list1, err := VaultListKeys(v, regexp.Regexp{})

	if len(list1) != 1 {
		t.Fail()
	}

	if err != nil {
		t.Fail()
	}
	vk := VaultKeyParameter{
		Vault:   v,
		KeyName: "TestkeyValue",
	}

	key, err := VaultGetKey(vk)

	if err != nil {
		t.Fail()
	}

	if !reflect.DeepEqual(key[0].Key, []byte(data["test"].(string))) {
		t.Fail()
	}

	list2, err := VaultListKeys(v2, regexp.Regexp{})

	if len(list2) != 1 {
		t.Fail()
	}

	if err != nil {
		t.Fail()
	}

	err = VaultDestroyCryptoContext(v)

	if err != nil {
		t.Fail()
	}

	err = VaultDestroyCryptoContext(v2)

	if err != nil {
		t.Fail()
	}
}
