// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestOptions_Valid(t *testing.T) {
	config := map[string]string{
		"trust_domain":        "example.org",
		"jwt_audience":        "vault",
		"jwt_auth_role":       "kms-role",
		"jwt_auth_mount_path": "spire-jwt",
		"key_name":            "test-key",
		"mount_path":          "my-transit",
		"address":             "http://localhost:8200",
		"spiffe_socket_path":  "unix:///tmp/custom.sock",
		"disable_renewal":     "true",
		"key_id_prefix":       "pref-",
		"tls_skip_verify":     "true",
	}

	opts, err := GetOpts(wrapping.WithConfigMap(config))
	require.NoError(t, err)
	require.NotNil(t, opts)
	require.Equal(t, "example.org", opts.TrustDomain.String())
	require.Equal(t, "vault", opts.JwtAudience)
	require.Equal(t, "kms-role", opts.JwtAuthRole)
	require.Equal(t, "spire-jwt", opts.JwtAuthMountPath)
	require.Equal(t, "test-key", opts.KeyName)
	require.Equal(t, "my-transit", opts.MountPath)
	require.Equal(t, "http://localhost:8200", opts.Address)
	require.Equal(t, "unix:///tmp/custom.sock", opts.SpiffeSocketPath)
	require.True(t, opts.DisableRenewal)
	require.Equal(t, "pref-", opts.KeyIdPrefix)
	require.True(t, opts.TLSSkipVerify)
	require.NotNil(t, opts.SpiffeMtlsEnabled)
	require.False(t, *opts.SpiffeMtlsEnabled)
}

func TestOptions_Defaults(t *testing.T) {
	config := map[string]string{
		"trust_domain":  "example.org",
		"jwt_audience":  "vault",
		"jwt_auth_role": "kms-role",
		"key_name":      "test-key",
	}

	opts, err := GetOpts(wrapping.WithConfigMap(config))
	require.NoError(t, err)
	require.NotNil(t, opts)
	require.Equal(t, DefaultTransitMountPath, opts.MountPath)
	require.Equal(t, DefaultJWTAuthMountPath, opts.JwtAuthMountPath)
	require.Equal(t, DefaultTransitAddress, opts.Address)
	require.Equal(t, DefaultSpiffeSocketPath, opts.SpiffeSocketPath)
	require.False(t, opts.DisableRenewal)
	require.NotNil(t, opts.SpiffeMtlsEnabled)
	require.True(t, *opts.SpiffeMtlsEnabled) // Defaults to true for default https address
}

func TestOptions_SpiffeMtls(t *testing.T) {
	t.Run("explicit spiffe_mtls_enabled and spiffe_server_id", func(t *testing.T) {
		config := map[string]string{
			"trust_domain":        "example.org",
			"jwt_audience":        "vault",
			"jwt_auth_role":       "kms-role",
			"key_name":            "test-key",
			"address":             "https://openbao-transit:8200",
			"spiffe_mtls_enabled": "true",
			"spiffe_server_id":    "spiffe://example.org/openbao-transit",
		}

		opts, err := GetOpts(wrapping.WithConfigMap(config))
		require.NoError(t, err)
		require.NotNil(t, opts)
		require.NotNil(t, opts.SpiffeMtlsEnabled)
		require.True(t, *opts.SpiffeMtlsEnabled)
		require.Equal(t, "spiffe://example.org/openbao-transit", opts.SpiffeServerID.String())
	})

	t.Run("explicit spiffe_mtls_enabled disabled", func(t *testing.T) {
		config := map[string]string{
			"trust_domain":        "example.org",
			"jwt_audience":        "vault",
			"jwt_auth_role":       "kms-role",
			"key_name":            "test-key",
			"address":             "https://openbao-transit:8200",
			"spiffe_mtls_enabled": "false",
			"tls_ca_cert":         "/tmp/ca.crt",
			"tls_client_cert":     "/tmp/client.crt",
			"tls_client_key":      "/tmp/client.key",
		}

		opts, err := GetOpts(wrapping.WithConfigMap(config))
		require.NoError(t, err)
		require.NotNil(t, opts)
		require.NotNil(t, opts.SpiffeMtlsEnabled)
		require.False(t, *opts.SpiffeMtlsEnabled)
		require.Equal(t, "/tmp/ca.crt", opts.TLSCaCert)
		require.Equal(t, "/tmp/client.crt", opts.TLSClientCert)
	})
}

func TestOptions_MutualExclusivity(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]string
		errSubstr string
	}{
		{
			name: "spiffe_mtls_enabled with file-based client cert",
			config: map[string]string{
				"trust_domain":        "example.org",
				"jwt_audience":        "vault",
				"jwt_auth_role":       "kms-role",
				"key_name":            "test-key",
				"spiffe_mtls_enabled": "true",
				"tls_client_cert":     "/tmp/client.crt",
				"tls_client_key":      "/tmp/client.key",
			},
			errSubstr: "cannot configure file-based client certificate/key",
		},
		{
			name: "spiffe_mtls_enabled with file-based CA cert",
			config: map[string]string{
				"trust_domain":        "example.org",
				"jwt_audience":        "vault",
				"jwt_auth_role":       "kms-role",
				"key_name":            "test-key",
				"spiffe_mtls_enabled": "true",
				"tls_ca_cert":         "/tmp/ca.crt",
			},
			errSubstr: "cannot configure file-based CA certificate",
		},
		{
			name: "spiffe_server_id with file-based client cert",
			config: map[string]string{
				"trust_domain":     "example.org",
				"jwt_audience":     "vault",
				"jwt_auth_role":    "kms-role",
				"key_name":         "test-key",
				"spiffe_server_id": "spiffe://example.org/openbao-transit",
				"tls_client_cert":  "/tmp/client.crt",
				"tls_client_key":   "/tmp/client.key",
			},
			errSubstr: "cannot configure 'spiffe_server_id' alongside file-based TLS parameters",
		},
		{
			name: "spiffe_server_id when spiffe_mtls_enabled is false",
			config: map[string]string{
				"trust_domain":        "example.org",
				"jwt_audience":        "vault",
				"jwt_auth_role":       "kms-role",
				"key_name":            "test-key",
				"spiffe_mtls_enabled": "false",
				"spiffe_server_id":    "spiffe://example.org/openbao-transit",
			},
			errSubstr: "cannot configure 'spiffe_server_id' when SPIFFE dynamic mTLS ('spiffe_mtls_enabled') is explicitly disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetOpts(wrapping.WithConfigMap(tt.config))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}

func TestOptions_MissingFields(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]string
		errSubstr string
	}{
		{
			name: "missing trust_domain",
			config: map[string]string{
				"jwt_audience":  "vault",
				"jwt_auth_role": "kms-role",
				"key_name":      "test-key",
			},
			errSubstr: "trust_domain is required",
		},
		{
			name: "invalid trust_domain",
			config: map[string]string{
				"trust_domain":  "invalid domain with spaces",
				"jwt_audience":  "vault",
				"jwt_auth_role": "kms-role",
				"key_name":      "test-key",
			},
			errSubstr: "invalid trust_domain",
		},
		{
			name: "missing jwt_audience",
			config: map[string]string{
				"trust_domain":  "example.org",
				"jwt_auth_role": "kms-role",
				"key_name":      "test-key",
			},
			errSubstr: "jwt_audience is required",
		},
		{
			name: "missing jwt_auth_role",
			config: map[string]string{
				"trust_domain": "example.org",
				"jwt_audience": "vault",
				"key_name":     "test-key",
			},
			errSubstr: "jwt_auth_role is required",
		},
		{
			name: "missing key_name",
			config: map[string]string{
				"trust_domain":  "example.org",
				"jwt_audience":  "vault",
				"jwt_auth_role": "kms-role",
			},
			errSubstr: "key_name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetOpts(wrapping.WithConfigMap(tt.config))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}
