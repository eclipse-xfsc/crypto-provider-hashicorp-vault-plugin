# Hashicorp-vault-provider

## Introduction

This plugin provides key usage by using the hashicorp vault signing engine. 

## Usage

Start the Plugin under the desired adress and connect any service to it. 

Environment Variables: 

|BTC|Example Value|
|--------|-----|
|bc1q9zffdkzqej2gu6x4kngcue262t5k22lfy6az7p|0.0.0.0:50051|
|bc1qv2nutw6yxqfh82830z52l8kq4cyktm6s258qfv|0.0.0.0:50051|


  |ETH|Example Value|
|--------|-----|
|0xdbadc5e8b4078164960b9460d925f24403305385|0.0.0.0:50051|


## Security Advice

Before using this module, ensure that the used token has the roles for that functionality which you are planning. The root token of the vault can generate/delete keys etc. but this may not be in the intention of your application. Select the token carefully and give them just rights which the application need. Additionally generate the keys manually if required or protect them from deletion etc. 
