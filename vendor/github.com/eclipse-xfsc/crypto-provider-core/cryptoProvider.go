package core

import (
	"os"
	"plugin"

	"github.com/eclipse-xfsc/crypto-provider-core/types"
)

var provider types.CryptoProvider

func initialize(path string) {
	p, err := plugin.Open(path)
	if err != nil {
		panic(err)
	}

	v, err := p.Lookup("Plugin")
	if err != nil {
		panic(err)
	}
	provider = v.(types.CryptoProviderModule).GetCryptoProvider()
}

/*
Returns standard Cryptoengine which is shipped with the docker image and/or the local file system.
*/
func CryptoEngine() types.CryptoProvider {
	path := os.Getenv("CRYPTO_PLUGIN_PATH")

	if path == "" {
		path = "/etc/plugins"
	}

	initialize(path)
	return provider
}

/*
Allows it to switch the Plugin and reload a crypto engine from another path. Makes only sense when the file system contains more than one plugin. Mostly just for unit tests relevant.
*/
func CreateCryptoEngine(path string) types.CryptoProvider {
	if path == "" {
		return nil
	}
	initialize(path)
	return provider
}
