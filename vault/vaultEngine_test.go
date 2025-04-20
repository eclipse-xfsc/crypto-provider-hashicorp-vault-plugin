package vault

import (
	"context"
	"testing"
)

func Test_CreateClient(t *testing.T) {
	client := VaultGetClient()

	if client == nil {
		t.Fail()
	}
}

func Test_CreateDeleteEngine(t *testing.T) {
	client := VaultGetClient()

	v := VaultParameter{
		Client:      client,
		EnginePath:  "Test",
		Description: "Test2",
	}

	err := VaultCreateEngine(v)

	if err != nil {
		t.Fail()
	}

	b := VaultEngineExists(v)

	if !b {
		t.Fail()
	}

	err = VaultDeleteEngine(v)

	if err != nil {
		t.Fail()
	}

	b = VaultEngineExists(v)

	if b {
		t.Fail()
	}
}

func Test_CreateDeleteKVEngine(t *testing.T) {
	client := VaultGetClient()
	v := VaultParameter{
		Client:      client,
		Context:     context.Background(),
		EnginePath:  "Test",
		Description: "Test2",
		Engine:      KV,
	}

	err := VaultCreateEngine(v)

	if err != nil {
		t.Fail()
	}

	b := VaultEngineExists(v)

	if !b {
		t.Fail()
	}

	err = VaultDeleteEngine(v)

	if err != nil {
		t.Fail()
	}

	b = VaultEngineExists(v)

	if b {
		t.Fail()
	}
}
