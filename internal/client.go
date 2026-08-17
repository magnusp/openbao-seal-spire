// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"sync"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/api/v2"
)

type TransitClient interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
	Close()
	GetMountPath() string
	GetApiClient() *api.Client
}

type SpireTransitClient struct {
	lock            sync.RWMutex
	client          *api.Client
	spireClient     SpireClient
	lifetimeWatcher *api.LifetimeWatcher
	logger          hclog.Logger

	mountPath        string
	keyName          string
	jwtAuthRole      string
	jwtAuthMountPath string
	jwtAudience      string
	disableRenewal   bool
}

// NewSpireTransitClient creates and authenticates an OpenBao transit client using SPIRE JWT auth.
func NewSpireTransitClient(ctx context.Context, opts *Options, spireClient SpireClient) (*SpireTransitClient, *wrapping.WrapperConfig, error) {
	if opts.Options == nil {
		opts.Options = &wrapping.Options{}
	}

	logger := opts.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	var apiConfig *api.Config
	if !opts.WithDisallowEnvVars {
		apiConfig = api.DefaultConfig()
	} else {
		apiConfig = api.NewConfig()
		apiConfig.Address = DefaultTransitAddress
	}

	if opts.Address != "" {
		apiConfig.Address = opts.Address
	}

	tlsConfig := &api.TLSConfig{
		TLSServerName: opts.TLSServerName,
		Insecure:      opts.TLSSkipVerify,
	}

	hasTLSCaConfig := opts.TLSCaCert != "" || opts.TLSCaCertDir != "" || opts.TLSCaCertBytes != ""
	if hasTLSCaConfig {
		if !opts.WithDisallowEnvVars {
			tlsConfig.CACert = opts.TLSCaCert
			tlsConfig.CAPath = opts.TLSCaCertDir
		}
		tlsConfig.CACertBytes = []byte(opts.TLSCaCertBytes)
	}

	hasTLSConfig := (opts.TLSClientCert != "" && opts.TLSClientKey != "") || (opts.TLSClientCertBytes != "" && opts.TLSClientKeyBytes != "")
	if hasTLSConfig {
		if !opts.WithDisallowEnvVars {
			tlsConfig.ClientCert = opts.TLSClientCert
			tlsConfig.ClientKey = opts.TLSClientKey
		}
		tlsConfig.ClientCertBytes = []byte(opts.TLSClientCertBytes)
		tlsConfig.ClientKeyBytes = []byte(opts.TLSClientKeyBytes)
	}

	if tlsConfig.Insecure || tlsConfig.TLSServerName != "" || hasTLSCaConfig || hasTLSConfig {
		if err := apiConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	apiClient, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OpenBao API client: %w", err)
	}

	if opts.Namespace != "" {
		apiClient.SetNamespace(opts.Namespace)
	}

	c := &SpireTransitClient{
		client:           apiClient,
		spireClient:      spireClient,
		logger:           logger,
		mountPath:        opts.MountPath,
		keyName:          opts.KeyName,
		jwtAuthRole:      opts.JwtAuthRole,
		jwtAuthMountPath: opts.JwtAuthMountPath,
		jwtAudience:      opts.JwtAudience,
		disableRenewal:   opts.DisableRenewal,
	}

	// Perform initial authentication
	if err := c.authenticate(ctx); err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("failed initial SPIRE JWT authentication: %w", err)
	}

	wrapConfig := &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"address":             apiClient.Address(),
			"mount_path":          opts.MountPath,
			"key_name":            opts.KeyName,
			"jwt_auth_role":       opts.JwtAuthRole,
			"jwt_auth_mount_path": opts.JwtAuthMountPath,
			"trust_domain":        opts.TrustDomain.String(),
			"jwt_audience":        opts.JwtAudience,
		},
	}
	if opts.Namespace != "" {
		wrapConfig.Metadata["namespace"] = opts.Namespace
	}

	return c, wrapConfig, nil
}

// authenticate fetches a JWT-SVID from SPIRE and logs into OpenBao via the JWT auth backend.
func (c *SpireTransitClient) authenticate(ctx context.Context) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Stop any existing lifetime watcher before re-authenticating
	if c.lifetimeWatcher != nil {
		c.lifetimeWatcher.Stop()
		c.lifetimeWatcher = nil
	}

	jwtToken, err := c.spireClient.FetchJWTSVID(ctx, c.jwtAudience)
	if err != nil {
		return fmt.Errorf("error fetching JWT-SVID from SPIRE: %w", err)
	}

	loginPath := path.Join("auth", c.jwtAuthMountPath, "login")
	loginData := map[string]interface{}{
		"jwt":  jwtToken,
		"role": c.jwtAuthRole,
	}

	secret, err := c.client.Logical().WriteWithContext(ctx, loginPath, loginData)
	if err != nil {
		return fmt.Errorf("error authenticating with OpenBao JWT backend at %q: %w", loginPath, err)
	}
	if secret == nil || secret.Auth == nil {
		return errors.New("nil auth response received from OpenBao JWT login")
	}

	token := secret.Auth.ClientToken
	if token == "" {
		return errors.New("empty client token returned from OpenBao JWT login")
	}

	c.client.SetToken(token)

	if !c.disableRenewal && secret.Auth.Renewable {
		lifetimeWatcher, err := c.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{
			Secret: secret,
		})
		if err == nil {
			c.lifetimeWatcher = lifetimeWatcher
			go func() {
				for {
					select {
					case err := <-lifetimeWatcher.DoneCh():
						if err != nil {
							c.logger.Warn("token renewal finished with error, will re-authenticate on next request", "error", err)
						} else {
							c.logger.Debug("token renewal stopped")
						}
						return
					case <-lifetimeWatcher.RenewCh():
						c.logger.Trace("successfully renewed OpenBao client token")
					}
				}
			}()
			go lifetimeWatcher.Start()
		} else {
			c.logger.Warn("unable to initialize LifetimeWatcher for token renewal", "error", err)
		}
	}

	return nil
}

func (c *SpireTransitClient) Close() {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.lifetimeWatcher != nil {
		c.lifetimeWatcher.Stop()
		c.lifetimeWatcher = nil
	}
	if c.spireClient != nil {
		_ = c.spireClient.Close()
	}
}

func (c *SpireTransitClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	encPlaintext := base64.StdEncoding.EncodeToString(plaintext)
	encryptPath := path.Join(c.mountPath, "encrypt", c.keyName)

	resp, err := c.client.Logical().WriteWithContext(ctx, encryptPath, map[string]interface{}{
		"plaintext": encPlaintext,
	})
	if err != nil {
		// If unauthorized, attempt a re-authentication and retry once
		if isAuthError(err) {
			if authErr := c.authenticate(ctx); authErr == nil {
				resp, err = c.client.Logical().WriteWithContext(ctx, encryptPath, map[string]interface{}{
					"plaintext": encPlaintext,
				})
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("transit encrypt operation failed: %w", err)
	}
	if resp == nil || resp.Data == nil {
		return nil, errors.New("transit encrypt returned empty response")
	}

	ct, ok := resp.Data["ciphertext"].(string)
	if !ok || ct == "" {
		return nil, errors.New("ciphertext missing or invalid in transit encrypt response")
	}

	return []byte(ct), nil
}

func (c *SpireTransitClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	decryptPath := path.Join(c.mountPath, "decrypt", c.keyName)

	resp, err := c.client.Logical().WriteWithContext(ctx, decryptPath, map[string]interface{}{
		"ciphertext": string(ciphertext),
	})
	if err != nil {
		// If unauthorized, attempt a re-authentication and retry once
		if isAuthError(err) {
			if authErr := c.authenticate(ctx); authErr == nil {
				resp, err = c.client.Logical().WriteWithContext(ctx, decryptPath, map[string]interface{}{
					"ciphertext": string(ciphertext),
				})
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("transit decrypt operation failed: %w", err)
	}
	if resp == nil || resp.Data == nil {
		return nil, errors.New("transit decrypt returned empty response")
	}

	pt, ok := resp.Data["plaintext"].(string)
	if !ok || pt == "" {
		return nil, errors.New("plaintext missing or invalid in transit decrypt response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(pt)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode plaintext from transit: %w", err)
	}

	return plaintext, nil
}

func (c *SpireTransitClient) GetMountPath() string {
	return c.mountPath
}

func (c *SpireTransitClient) GetApiClient() *api.Client {
	return c.client
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return errors.Is(err, api.ErrSecretNotFound) ||
		containsSubstr(msg, "permission denied") ||
		containsSubstr(msg, "invalid token") ||
		containsSubstr(msg, "missing client token")
}

func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) > 0 && pathMatch(s, substr))
}

func pathMatch(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
