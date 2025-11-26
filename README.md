# Hashicorp-vault-provider

## Introduction

This plugin provides key usage by using the hashicorp vault signing engine. 

## Usage

Start the Plugin under the desired adress and connect any service to it. 

Environment Variables: 

|Variable|Example Value|
|--------|-----|
|CRYPTO_PROVIDER_HASHICORP_VAULT_ADDRESS|0.0.0.0:50051|

## Security Advice

Before using this module, ensure that the used token has the roles for that functionality which you are planning. The root token of the vault can generate/delete keys etc. but this may not be in the intention of your application. Select the token carefully and give them just rights which the application need. Additionally generate the keys manually if required or protect them from deletion etc. 
