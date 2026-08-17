// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SpireClient defines the interface for interacting with the SPIRE Workload API.
type SpireClient interface {
	// FetchJWTSVID requests a JWT-SVID for the given audience and ensures it matches the configured trust domain.
	FetchJWTSVID(ctx context.Context, audience string) (string, error)
	// Close shuts down the SPIRE client and releases resources.
	Close() error
}

type workloadSpireClient struct {
	client      *workloadapi.Client
	trustDomain spiffeid.TrustDomain
}

// NewSpireClient creates a new SpireClient connecting to the workload API at socketPath.
func NewSpireClient(ctx context.Context, socketPath string, trustDomain spiffeid.TrustDomain) (SpireClient, error) {
	var opts []workloadapi.ClientOption
	if socketPath != "" {
		opts = append(opts, workloadapi.WithAddr(socketPath))
	}

	client, err := workloadapi.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPIFFE workload API client: %w", err)
	}

	return &workloadSpireClient{
		client:      client,
		trustDomain: trustDomain,
	}, nil
}

func (s *workloadSpireClient) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
	svid, err := s.client.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		return "", fmt.Errorf("failed to fetch JWT-SVID from SPIRE workload API: %w", err)
	}

	if svid.ID.TrustDomain() != s.trustDomain {
		return "", fmt.Errorf("received SVID trust domain %q does not match configured trust domain %q",
			svid.ID.TrustDomain().String(), s.trustDomain.String())
	}

	return svid.Marshal(), nil
}

func (s *workloadSpireClient) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}
