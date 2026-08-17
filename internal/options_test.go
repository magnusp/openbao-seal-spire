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
