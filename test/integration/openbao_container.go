//go:build integration

// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type OpenBaoContainer struct {
	testcontainers.Container
	URI       string
	RootToken string
	Client    *api.Client
}

// StartOpenBaoContainer starts an OpenBao server in dev mode with Transit and JWT auth enabled.
func StartOpenBaoContainer(ctx context.Context) (*OpenBaoContainer, error) {
	rootToken := "root-integration-token"

	req := testcontainers.ContainerRequest{
		Image:        "openbao/openbao:latest",
		ExposedPorts: []string{"8200/tcp"},
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID":  rootToken,
			"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
		},
		WaitingFor: wait.ForHTTP("/v1/sys/health").
			WithPort("8200/tcp").
			WithStatusCodeMatcher(func(status int) bool {
				// 200 = active, 429 = standby, 472 = disaster recovery, 473 = performance standby
				return status == 200 || status == 429
			}).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start OpenBao container: %w", err)
	}

	ip, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get OpenBao container host: %w", err)
	}

	port, err := container.MappedPort(ctx, "8200")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get OpenBao container port: %w", err)
	}

	uri := fmt.Sprintf("http://%s:%s", ip, port.Port())

	apiConfig := api.DefaultConfig()
	apiConfig.Address = uri
	client, err := api.NewClient(apiConfig)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to create OpenBao client: %w", err)
	}
	client.SetToken(rootToken)

	return &OpenBaoContainer{
		Container: container,
		URI:       uri,
		RootToken: rootToken,
		Client:    client,
	}, nil
}
