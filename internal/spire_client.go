// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SpireClient defines the interface for interacting with the SPIRE Workload API.
type SpireClient interface {
	// FetchJWTSVID requests a JWT-SVID for the given audience and ensures it matches the configured trust domain.
	FetchJWTSVID(ctx context.Context, audience string) (string, error)
	// X509Source returns an in-memory X509Source for dynamic mTLS and trust bundle streaming.
	X509Source(ctx context.Context) (*workloadapi.X509Source, error)
	// Close shuts down the SPIRE client and releases resources.
	Close() error
}

type workloadSpireClient struct {
	client      *workloadapi.Client
	socketPath  string
	trustDomain spiffeid.TrustDomain

	mu         sync.Mutex
	x509Source *workloadapi.X509Source
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
		socketPath:  socketPath,
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

func (s *workloadSpireClient) X509Source(ctx context.Context) (*workloadapi.X509Source, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.x509Source != nil {
		return s.x509Source, nil
	}

	var srcOpts []workloadapi.X509SourceOption
	if s.socketPath != "" {
		srcOpts = append(srcOpts, workloadapi.WithClientOptions(workloadapi.WithAddr(s.socketPath)))
	}

	source, err := workloadapi.NewX509Source(ctx, srcOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPIFFE X509Source: %w", err)
	}

	s.x509Source = source
	return source, nil
}

func (s *workloadSpireClient) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	if s.x509Source != nil {
		if err := s.x509Source.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.x509Source = nil
	}

	if s.client != nil {
		if err := s.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.client = nil
	}

	return firstErr
}
