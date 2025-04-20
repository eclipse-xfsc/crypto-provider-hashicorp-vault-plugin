package vault

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	Transit string = "transit"
	KV      string = "kv"
)

var vaultClient *api.Client

func vaultConfig() VaultClientConfig {
	return VaultClientConfig{
		Address: viper.GetString("VAULT_ADRESS"),
		Token:   viper.GetString("VAULT_TOKEN"),
	}
}

func VaultCreateCryptoContext(v VaultParameter) error {
	if vaultClient != nil {

		b := VaultEngineExists(v)

		if !b {
			err := VaultCreateEngine(v)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func VaultDestroyCryptoContext(v VaultParameter) error {
	if vaultClient != nil {
		b := VaultEngineExists(v)

		if b {
			err := VaultDeleteEngine(v)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func VaultGetClient() *vault.Client {

	if vaultClient == nil || vaultClient.Address() == "" {
		viper.SetConfigFile("../.env")
		viper.ReadInConfig()
		viper.AutomaticEnv()
		cfg := vault.DefaultConfig()
		cfg.Address = vaultConfig().Address
		cfg.HttpClient = http.DefaultClient
		client, err := vault.NewClient(cfg)
		token := vaultConfig().Token
		if err != nil {
			logrus.Fatal(err)
		}

		client.SetToken(token)

		if _, err = client.Sys().Capabilities(token, pathSysMounts); err != nil {
			logrus.Fatal(err)
			return nil
		}
		vaultClient = client
	}

	return vaultClient
}

func VaultEngineExists(vaultParameter VaultParameter) bool {
	vaultParameter.SetEngine(vaultParameter.Engine)
	client := vaultParameter.Client
	_, err := client.Sys().MountConfig(vaultParameter.EnginePath)
	return err == nil
}

func VaultCreateEngine(vaultParameter VaultParameter) error {
	client := vaultParameter.Client

	// Enable engine
	mi := vault.MountInput{}

	vaultParameter.SetEngine(vaultParameter.Engine)

	mi.Type = vaultParameter.Engine

	if vaultParameter.Description == "" {
		mi.Description = "Auto Generated Engine"
	} else {
		mi.Description = vaultParameter.Description
	}

	if vaultParameter.Engine == KV {
		mi.Options = map[string]string{
			"version": "2",
		}
	}

	err := client.Sys().Mount(vaultParameter.EnginePath, &mi)
	if err != nil {
		err = fmt.Errorf("unable to enable engine: %v", err)
		return err
	}

	return nil
}

func VaultDeleteEngine(vaultParameter VaultParameter) error {
	vaultParameter.SetEngine(vaultParameter.Engine)
	client := vaultParameter.Client
	// Disable engine
	err := client.Sys().Unmount(vaultParameter.EnginePath)
	if err != nil {
		err = fmt.Errorf("unable to disable engine: %v", err)
		return err
	}

	return nil
}
