// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const Type wrapping.WrapperType = "transit-spire"

// Wrapper is a KMS wrapper that leverages OpenBao/Vault's Transit secret engine
// with SPIRE Workload API JWT-SVID authentication.
type Wrapper struct {
	logger       hclog.Logger
	client       TransitClient
	currentKeyId *atomic.Value
	keyIdPrefix  string
	spireClient  SpireClient // for testing injection if needed
}

var (
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

// NewWrapper creates a new SPIRE Transit wrapper.
func NewWrapper() *Wrapper {
	w := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	w.currentKeyId.Store("")
	return w
}

// WithCustomSpireClient allows injecting a mock or custom SpireClient (used primarily in tests).
func (w *Wrapper) WithCustomSpireClient(sc SpireClient) *Wrapper {
	w.spireClient = sc
	return w
}

// SetConfig initializes the wrapper using the provided options.
func (w *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	w.logger = opts.Logger
	if w.logger == nil {
		w.logger = hclog.NewNullLogger()
	}

	spireClient := w.spireClient
	if spireClient == nil {
		var err error
		spireClient, err = NewSpireClient(ctx, opts.SpiffeSocketPath, opts.TrustDomain)
		if err != nil {
			return nil, err
		}
	}

	client, wrapConfig, err := NewSpireTransitClient(ctx, opts, spireClient)
	if err != nil {
		_ = spireClient.Close()
		return nil, err
	}

	w.client = client
	w.keyIdPrefix = opts.KeyIdPrefix

	// Test encrypt to verify connectivity and initialize the current key id
	if _, err := w.Encrypt(ctx, []byte("a")); err != nil {
		client.Close()
		return nil, err
	}

	return wrapConfig, nil
}

// Init is called during core.Initialize.
func (w *Wrapper) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Finalize is called during shutdown.
func (w *Wrapper) Finalize(_ context.Context, _ ...wrapping.Option) error {
	if w.client != nil {
		w.client.Close()
	}
	return nil
}

// Type returns the WrapperType for this implementation.
func (w *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

// KeyId returns the last known key id.
func (w *Wrapper) KeyId(_ context.Context) (string, error) {
	if val := w.currentKeyId.Load(); val != nil {
		return val.(string), nil
	}
	return "", nil
}

// Encrypt encrypts plaintext using the Transit engine.
func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	ciphertext, err := w.client.Encrypt(ctx, plaintext)
	if err != nil {
		return nil, err
	}

	splitKey := strings.Split(string(ciphertext), ":")
	if len(splitKey) != 3 {
		return nil, errors.New("invalid ciphertext format returned from transit")
	}

	keyId := w.keyIdPrefix + splitKey[1]
	w.currentKeyId.Store(keyId)

	return &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: keyId,
		},
	}, nil
}

// Decrypt decrypts ciphertext using the Transit engine.
func (w *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	if in == nil || len(in.Ciphertext) == 0 {
		return nil, errors.New("missing ciphertext to decrypt")
	}
	return w.client.Decrypt(ctx, in.Ciphertext)
}

// GetClient returns the underlying TransitClient.
func (w *Wrapper) GetClient() TransitClient {
	return w.client
}
