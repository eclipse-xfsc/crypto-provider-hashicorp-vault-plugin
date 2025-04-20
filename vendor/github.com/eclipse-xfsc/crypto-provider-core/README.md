# Crypto Core

## Introduction

This package is a library to abstract crypto providers for go. It uses plugin system. The providers can be loaded during startup by adding the respective module in the local folder.

## Building

Here is the [README.md](https://gitlab.eclipse.org/eclipse/xfsc/dev-ops/building/go-plugin/-/blob/main/README.md#building-go-services-with-plugin-based-dependencies) describing the specifics of build process for services, where the dependency is used.

## Usage

Implement/Choose a plugin which implements the commonProvider Interface and put it in the docker container in an folder which is identified by the environment variable CRYPTO_CORE_MODULE_PATH next to your application (e.g. in Docker File)

## Compilation of Modules

Compilation

```
go build -buildmode=plugin
```

Plugin

```
func GetCryptoProvider() CryptoProvider {
    return provider
}

var Plugin CryptoProviderModule //export Plugin Symbol, dont change this name:) 
```

## Configuration

Following environment variables are required:

CRYPTO_PLUGIN_PATH - path from where to fetch the compiled plugin .so file - default: /etc/plugins

## Problem Solving

The compatibility of the plugins with this provider it's sometimes tricky, because the versions of go, each lib version etc. must match 100% otherwise it will reject it during startup.
