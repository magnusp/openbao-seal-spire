// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/magnusp/openbao-seal-spire/internal"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	kmsplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
)

func main() {
	kmsplugin.Serve(&kmsplugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return internal.NewWrapper()
		},
	})
}
