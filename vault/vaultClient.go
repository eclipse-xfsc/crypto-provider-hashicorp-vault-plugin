package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/eclipse-xfsc/crypto-provider-core/types"
	"github.com/eclipse-xfsc/crypto-provider-hashicorp-vault-plugin/utils"
	vaultpkg "github.com/hashicorp/vault/api"
)

const (
	pathSysMounts   = "/v1/sys/mounts"
	authTokenHeader = "X-Vault-Token"
	engineError     = "this operation is not available for other engines than transit"
)

type VaultClientConfig struct {
	Address string
	Token   string
}

type VaultKeyDescription struct {
	KeyName string
	Key     []byte
	Type    types.KeyType
	Version string
	Params  json.RawMessage
}

type VaultParameter struct {
	Client      *vaultpkg.Client
	Context     context.Context
	EnginePath  string
	Description string
	Engine      string
}
type VaultKeyParameter struct {
	KeyName string
	Vault   VaultParameter
	Params  json.RawMessage
}

type VaultKeyTypeParameter struct {
	KeyParameter VaultKeyParameter
	KeyType      types.KeyType
}

type VaultHashParameter struct {
	KeyParameter  VaultKeyParameter
	HashAlgorithm types.HashAlgorithm
}

func (p *VaultParameter) SetEngine(engine string) {
	p.Engine = engine

	if engine == "" {
		p.Engine = Transit
	}
}

func engineExists(vaultParameter *VaultParameter) error {
	vaultParameter.SetEngine(vaultParameter.Engine)

	b := VaultEngineExists(*vaultParameter)

	if !b {
		err := errors.New("crypto engine not found")
		return &types.CryptoContextError{Err: err}
	}
	return nil
}

func VaultGetNamespaces(parameter VaultParameter) ([]string, error) {
	engines, err := parameter.Client.Sys().ListMounts()
	if err != nil {
		if e, ok := err.(*vaultpkg.ResponseError); ok {
			return nil, e
		}
		return nil, err
	}

	var namespaces []string
	namespaces = make([]string, 0)
	for name, engine := range engines {
		if engine.Type == parameter.Engine {

			if parameter.EnginePath != "" {
				if strings.Contains(name, parameter.EnginePath) {
					n := strings.Trim(name, "/")
					namespaces = append(namespaces, n)
				}
			} else {
				n := strings.Trim(name, "/")
				namespaces = append(namespaces, n)
			}
		}
	}

	return namespaces, nil
}

func VaultGetKey(vaultParameter VaultKeyParameter) ([]VaultKeyDescription, error) {

	err := engineExists(&vaultParameter.Vault)

	if err != nil {
		return nil, err
	}

	if vaultParameter.Vault.Engine == Transit {

		URL := "/v1/" + vaultParameter.Vault.EnginePath + "/keys/" + vaultParameter.KeyName
		body := make(map[string]interface{})

		return basicVaultCall[map[string]interface{}, []VaultKeyDescription]("GET", URL, body, "keys", func(keys map[string]interface{}, data map[string]interface{}) ([]VaultKeyDescription, error) {
			var m = make([]VaultKeyDescription, 0)
			t := data["type"].(string)
			var inter interface{}
			for i, v := range keys {
				if reflect.TypeOf(v) == reflect.MapOf(reflect.TypeOf("string"), reflect.TypeOf(&inter).Elem()) {
					key := v.(map[string]interface{})
					pubkey := []byte(key["public_key"].(string))

					if t == string(types.Ed25519) {
						dec, err := base64.StdEncoding.DecodeString(string(pubkey))
						if err != nil {
							return nil, err
						}

						bytes, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(dec))

						if err != nil {
							return nil, err
						}

						pemBlock := &pem.Block{
							Type:  "PUBLIC KEY",
							Bytes: bytes,
						}

						pubkey_bytes := pem.EncodeToMemory(pemBlock)

						pubkey = []byte(pubkey_bytes)
					}

					desc := VaultKeyDescription{
						KeyName: vaultParameter.KeyName,
						Type:    types.KeyType(t),
						Version: i,
						Key:     pubkey,
					}
					m = append(m, desc)
				} else {
					desc := VaultKeyDescription{
						KeyName: vaultParameter.KeyName,
						Type:    types.KeyType(t),
						Version: i,
						Key:     nil,
					}
					m = append(m, desc)
				}
			}
			return m, nil
		}, func(status int, errs []string, fail func() ([]VaultKeyDescription, error)) ([]VaultKeyDescription, error) {
			if status == http.StatusNotFound && len(errs) == 0 {
				return []VaultKeyDescription{}, nil
			} else {
				return fail()
			}
		}, vaultParameter.Vault)
	}

	if vaultParameter.Vault.Engine == KV {
		URL := "/v1/" + vaultParameter.Vault.EnginePath + "/data/" + vaultParameter.KeyName
		body := make(map[string]interface{})

		return basicVaultCall[map[string]interface{}, []VaultKeyDescription]("GET", URL, body, "", func(keys map[string]interface{}, data map[string]interface{}) ([]VaultKeyDescription, error) {
			var m = make([]VaultKeyDescription, 0)
			t, ok := data["metadata"]
			var version string
			if ok {
				meta := t.(map[string]interface{})
				v := meta["version"].(float64)
				version = fmt.Sprintf("%f", v)
			} else {
				version = "1"
			}

			b, err := json.Marshal(keys)

			if err != nil {
				return nil, err
			}

			for _, v := range keys["data"].(map[string]interface{}) {
				desc := VaultKeyDescription{
					KeyName: vaultParameter.KeyName,
					Key:     []byte(v.(string)),
					Type:    types.KeyValue,
					Version: version,
					Params:  b,
				}
				m = append(m, desc)
			}

			return m, nil
		}, func(status int, errs []string, fail func() ([]VaultKeyDescription, error)) ([]VaultKeyDescription, error) {
			if status == http.StatusNotFound && len(errs) == 0 {
				return []VaultKeyDescription{}, nil
			} else {
				return fail()
			}
		}, vaultParameter.Vault)
	}

	return nil, errors.ErrUnsupported
}

func VaultListKeys(vaultParameter VaultParameter, regex regexp.Regexp) ([]string, error) {

	err := engineExists(&vaultParameter)

	if err != nil {
		return nil, err
	}

	if vaultParameter.Engine == Transit {

		URL := "/v1/" + vaultParameter.EnginePath + "/keys"
		body := make(map[string]interface{})

		if regex.String() == "" {
			reg, _ := regexp.Compile(".*")
			regex = *reg
		}

		result, err := basicVaultCall[interface{}, []string]("LIST", URL, body, "keys", func(keys interface{}, data map[string]interface{}) ([]string, error) {
			var list = make([]string, 0)
			for _, v := range keys.([]interface{}) {
				if regex.MatchString(v.(string)) {
					list = append(list, v.(string))
				}
			}
			return list, nil
		}, nil, vaultParameter)

		///Fix for empty list reponse, which is not really a error, when the engine exists, but engine contains no keys.
		if len(result) == 0 && err != nil {
			if strings.Contains(err.Error(), "404") {
				err = nil
				result = []string{}
			}
		}

		return result, err
	}

	if vaultParameter.Engine == KV {
		URL := "/v1/" + vaultParameter.EnginePath + "/metadata"
		body := make(map[string]interface{})

		if regex.String() == "" {
			reg, _ := regexp.Compile(".*")
			regex = *reg
		}

		return basicVaultCall[interface{}, []string]("LIST", URL, body, "keys", func(keys interface{}, data map[string]interface{}) ([]string, error) {
			var list = make([]string, 0)
			for _, v := range keys.([]interface{}) {
				if regex.MatchString(v.(string)) {
					list = append(list, v.(string))
				}
			}
			return list, nil
		}, nil, vaultParameter)
	}

	return nil, errors.ErrUnsupported
}

func VaultCreateKey(vaultParameter VaultKeyTypeParameter) error {

	err := engineExists(&vaultParameter.KeyParameter.Vault)

	if err != nil {
		return err
	}

	var params map[string]interface{}
	if vaultParameter.KeyParameter.Params != nil {
		err = json.Unmarshal(vaultParameter.KeyParameter.Params, &params)
	}

	if err != nil {
		return err
	}

	var resp *http.Response
	method := "POST"

	if vaultParameter.KeyParameter.Vault.Engine == Transit {

		body := make(map[string]interface{})
		body["type"] = string(vaultParameter.KeyType)
		p, ok := params["derived"]
		derived := false
		exportable := false
		if ok {
			derived = p.(bool)
		}

		body["derived"] = derived
		p, ok = params["exportable"]
		if ok {
			exportable = p.(bool)
		}
		body["exportable"] = exportable

		jsonBody, _ := json.Marshal(body)

		createURL := vaultParameter.KeyParameter.Vault.Client.Address() + "/v1/" +
			vaultParameter.KeyParameter.Vault.EnginePath + "/keys/" + vaultParameter.KeyParameter.KeyName

		request, err := http.NewRequest(method, createURL, strings.NewReader(string(jsonBody)))

		if err != nil {
			return err
		}

		request.Header.Set("Content-type", "application/json")
		request.Header.Set(authTokenHeader, vaultParameter.KeyParameter.Vault.Client.Token())

		resp, err = http.DefaultClient.Do(request)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
				configURL := vaultParameter.KeyParameter.Vault.Client.Address() + "/v1/" +
					vaultParameter.KeyParameter.Vault.EnginePath + "/keys/" + vaultParameter.KeyParameter.KeyName + "/config"
				configBody := make(map[string]interface{})
				configBody["deletion_allowed"] = true
				configJsonBody, _ := json.Marshal(configBody)

				request, err := http.NewRequest(method, configURL, strings.NewReader(string(configJsonBody)))

				if err != nil {
					return err
				}

				request.Header.Set("Content-type", "application/json")
				request.Header.Set(authTokenHeader, vaultParameter.KeyParameter.Vault.Client.Token())

				resp, err = http.DefaultClient.Do(request)
				if err == nil {
					defer resp.Body.Close()
					if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
						return nil
					} else {
						err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, utils.ExtractHttpBody(resp.Body))
						return err
					}
				} else {
					return err
				}
			} else {
				err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, utils.ExtractHttpBody(resp.Body))
				return err
			}
		} else {
			return err
		}
	}

	if vaultParameter.KeyParameter.Vault.Engine == KV {
		data := make(map[string]interface{})

		if vaultParameter.KeyParameter.Params == nil {
			return errors.New("no params defined")
		}

		data["data"] = vaultParameter.KeyParameter.Params

		b, err := json.Marshal(data)

		if err != nil {
			return err
		}

		createURL := vaultParameter.KeyParameter.Vault.Client.Address() + "/v1/" +
			vaultParameter.KeyParameter.Vault.EnginePath + "/data/" + vaultParameter.KeyParameter.KeyName

		request, err := http.NewRequest(method, createURL, bytes.NewReader(b))

		if err != nil {
			return err
		}

		request.Header.Set("Content-type", "application/json")
		request.Header.Set(authTokenHeader, vaultParameter.KeyParameter.Vault.Client.Token())

		resp, err = http.DefaultClient.Do(request)

		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
				return nil
			} else {
				err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, utils.ExtractHttpBody(resp.Body))
				return err
			}
		} else {
			return err
		}

	}

	return errors.ErrUnsupported
}

func VaultDeleteKey(vaultParameter VaultKeyParameter) error {

	err := engineExists(&vaultParameter.Vault)

	if err != nil {
		return err
	}

	if vaultParameter.Vault.Engine == Transit {
		URL := "/v1/" + vaultParameter.Vault.EnginePath + "/keys/" + vaultParameter.KeyName
		_, err = basicVaultCall[map[string]interface{}, interface{}](http.MethodDelete, URL, make(map[string]any), "", nil, nil, vaultParameter.Vault)
	}

	if vaultParameter.Vault.Engine == KV {
		URL := "/v1/" + vaultParameter.Vault.EnginePath + "/metadata/" + vaultParameter.KeyName
		_, err = basicVaultCall[map[string]interface{}, interface{}](http.MethodDelete, URL, make(map[string]any), "", nil, nil, vaultParameter.Vault)
	}

	return err
}

func VaultRotateKey(vaultParameter VaultKeyParameter) error {
	err := engineExists(&vaultParameter.Vault)

	if vaultParameter.Vault.Engine != Transit {
		return errors.New(engineError)
	}

	if err != nil {
		return err
	}

	URL := "/v1/" + vaultParameter.Vault.EnginePath + "/keys/" + vaultParameter.KeyName + "/rotate"

	_, err = basicVaultCall[map[string]interface{}, interface{}](http.MethodPost, URL, make(map[string]any), "", nil, nil, vaultParameter.Vault)
	return err
}

func VaultHashData(vaultParameter VaultParameter, hashAlgorithm types.HashAlgorithm, data []byte) ([]byte, error) {

	err := engineExists(&vaultParameter)

	if vaultParameter.Engine != Transit {
		return nil, errors.New(engineError)
	}

	if err != nil {
		return nil, err
	}

	URL := "/v1/" +
		vaultParameter.EnginePath + "/hash/" + string(hashAlgorithm)

	body := make(map[string]interface{})
	body["input"] = b64.StdEncoding.EncodeToString(data)

	return basicVaultCall("POST", URL, body, "sum", convertB64, nil, vaultParameter)
}

func VaultGenerateRandom(vaultParameter VaultParameter, number int) ([]byte, error) {

	err := engineExists(&vaultParameter)

	if vaultParameter.Engine != Transit {
		return nil, errors.New(engineError)
	}

	if err != nil {
		return nil, err
	}

	URL := "/v1/" + vaultParameter.EnginePath + "/random/" + strconv.Itoa(number)

	body := make(map[string]interface{})
	body["format"] = "base64"

	return basicVaultCall("POST", URL, body, "random_bytes", convertB64, nil, vaultParameter)
}

func VaultVerifyData(vaultParameter VaultHashParameter, data []byte, signature []byte) (bool, error) {
	if types.ValidateHashFunction(vaultParameter.HashAlgorithm) || vaultParameter.HashAlgorithm == "default" {

		err := engineExists(&vaultParameter.KeyParameter.Vault)

		if vaultParameter.KeyParameter.Vault.Engine != Transit {
			return false, errors.New(engineError)
		}

		if err != nil {
			return false, err
		}

		URL := "/v1/" +
			vaultParameter.KeyParameter.Vault.EnginePath + "/verify/" +
			vaultParameter.KeyParameter.KeyName

		if vaultParameter.HashAlgorithm != "default" {
			URL = URL + "/" + string(vaultParameter.HashAlgorithm)
		}

		body := make(map[string]interface{})
		body["input"] = b64.StdEncoding.EncodeToString(data)
		body["signature"] = "vault:v1:" + b64.RawURLEncoding.EncodeToString(signature)
		body["marshaling_algorithm"] = "jws"

		result, err := basicVaultCall("POST", URL, body, "valid", func(b bool, data map[string]interface{}) (bool, error) {
			return b, nil
		}, nil, vaultParameter.KeyParameter.Vault)

		if err == nil {
			return result, nil
		}

		return false, err
	}
	return false, errors.New("invalid hash function")
}

func VaultSignData(vaultParameter VaultHashParameter, data []byte) ([]byte, error) {
	if types.ValidateHashFunction(vaultParameter.HashAlgorithm) || vaultParameter.HashAlgorithm == "default" {

		err := engineExists(&vaultParameter.KeyParameter.Vault)

		if vaultParameter.KeyParameter.Vault.Engine != Transit {
			return nil, errors.New(engineError)
		}

		if err != nil {
			return nil, err
		}

		URL := "/v1/" +
			vaultParameter.KeyParameter.Vault.EnginePath + "/sign/" +
			vaultParameter.KeyParameter.KeyName

		if vaultParameter.HashAlgorithm != "default" {
			URL = URL + "/" + string(vaultParameter.HashAlgorithm)
		}

		body := make(map[string]interface{})
		body["input"] = b64.StdEncoding.EncodeToString(data)
		body["marshaling_algorithm"] = "jws"
		return basicVaultCall("POST", URL, body, "signature", convertB64, nil, vaultParameter.KeyParameter.Vault)
	}
	return nil, errors.New("invalid hash function")
}

func VaultEncrypt(vaultParameter VaultKeyParameter, data []byte) ([]byte, error) {

	err := engineExists(&vaultParameter.Vault)

	if vaultParameter.Vault.Engine != Transit {
		return nil, errors.New(engineError)
	}

	if err != nil {
		return nil, err
	}

	URL := "/v1/" +
		vaultParameter.Vault.EnginePath + "/encrypt/" +
		vaultParameter.KeyName

	body := make(map[string]interface{})
	body["plaintext"] = b64.StdEncoding.EncodeToString(data)

	return basicVaultCall("POST", URL, body, "ciphertext", convertB64, nil, vaultParameter.Vault)
}

func VaultDecrypt(vaultParameter VaultKeyParameter, data []byte) ([]byte, error) {
	err := engineExists(&vaultParameter.Vault)

	if vaultParameter.Vault.Engine != Transit {
		return nil, errors.New(engineError)
	}

	if err != nil {
		return nil, err
	}

	URL := "/v1/" +
		vaultParameter.Vault.EnginePath + "/decrypt/" +
		vaultParameter.KeyName

	body := make(map[string]interface{})
	body["ciphertext"] = "vault:v1:" + b64.StdEncoding.EncodeToString(data)

	return basicVaultCall[string](http.MethodPost, URL, body, "plaintext", convertB64, nil, vaultParameter.Vault)
}

func VaultCreateEngineOverRest(vaultParameter VaultParameter) error {
	vaultParameter.SetEngine(vaultParameter.Engine)
	body := make(map[string]interface{})
	body["type"] = vaultParameter.Engine
	if vaultParameter.Description == "" {
		body["description"] = "Auto Generated Engine"
	} else {
		body["description"] = vaultParameter.Description
	}
	if vaultParameter.Engine == KV {
		body["options"] = map[string]string{
			"version": "2",
		}
	}
	URL := "/v1/sys/mounts/" + vaultParameter.EnginePath
	_, err := basicVaultCall[map[string]interface{}, interface{}](http.MethodPost, URL, body, "", nil, nil, vaultParameter)
	return err
}

func basicVaultCall[ReturnType any, OutputType any](
	method string,
	url string,
	requestBody map[string]any,
	outputField string,
	transformFunc func(ReturnType, map[string]interface{}) (OutputType, error),
	failTransformFunc func(int, []string, func() (OutputType, error)) (OutputType, error),
	client VaultParameter) (OutputType, error) {
	jsonBody, _ := json.Marshal(requestBody)

	request, err := http.NewRequest(method, client.Client.Address()+url, strings.NewReader(string(jsonBody)))

	var returnValue OutputType

	if err != nil {
		return returnValue, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(authTokenHeader, "*****")

	if client.Context != nil {
		request = request.WithContext(client.Context)
	}
	reqPretty, _ := httputil.DumpRequestOut(request, true)
	request.Header.Set(authTokenHeader, client.Client.Token())

	resp, err := http.DefaultClient.Do(request)
	if err == nil {
		if resp.StatusCode == http.StatusNoContent {
			return returnValue, nil
		}
		defer resp.Body.Close()
		body := utils.ExtractHttpBody(resp.Body)
		result := make(map[string]interface{})
		err = json.Unmarshal([]byte(body), &result)
		if err != nil {
			return returnValue, err
		}
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			data := result["data"]
			var out interface{}
			var ok bool
			if outputField == "" {
				out, ok = data, true
			} else {
				out, ok = data.(map[string]interface{})[outputField]
			}
			if ok {
				if transformFunc != nil {
					return transformFunc(out.(ReturnType), data.(map[string]interface{}))
				} else {
					return out.(OutputType), nil
				}
			}
		} else {
			errs := []string{"unknown error"}

			if tmp, ok := result["errors"]; ok {
				tmp1 := tmp.([]interface{})
				errs = make([]string, len(tmp1))
				for i, e := range tmp1 {
					errs[i] = e.(string)
				}
			}

			var fail = func() (OutputType, error) {
				return returnValue, fmt.Errorf("vault responce with status %s with errors: %s. after request %s ",
					resp.Status,
					strings.Join(errs, ", "),
					reqPretty)
			}
			if failTransformFunc != nil {
				return failTransformFunc(resp.StatusCode, errs, fail)
			} else {
				return fail()
			}

		}
	}
	return returnValue, err
}

func convertB64(val string, data map[string]interface{}) ([]byte, error) {
	var bytes []byte
	var err error

	if strings.Contains(val, "vault:v1:") {
		bytes, err = b64.StdEncoding.DecodeString(val[9:]) //cut of vault:v1:
		if err != nil {
			bytes, err = b64.RawURLEncoding.DecodeString(val[9:])
		}
	} else {
		bytes, err = b64.StdEncoding.DecodeString(val)
		if err != nil {
			bytes, err = b64.RawURLEncoding.DecodeString(val[9:])
		}
	}
	if err == nil {
		return bytes, nil
	}
	return nil, err
}
