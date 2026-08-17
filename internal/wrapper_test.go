// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

type mockSpireClient struct {
	token       string
	fetchCount  atomic.Int32
	trustDomain spiffeid.TrustDomain
	err         error
}

func (m *mockSpireClient) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
	m.fetchCount.Add(1)
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

func (m *mockSpireClient) X509Source(ctx context.Context) (*workloadapi.X509Source, error) {
	return nil, nil
}

func (m *mockSpireClient) Close() error {
	return nil
}

func TestWrapper_MockTransitServer(t *testing.T) {
	ctx := context.Background()

	var loginCalls atomic.Int32
	var encryptCalls atomic.Int32
	var decryptCalls atomic.Int32

	// Setup mock OpenBao HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/v1/auth/jwt/login"):
			loginCalls.Add(1)
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)

			if body["jwt"] != "valid-jwt-token" || body["role"] != "spire-role" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"invalid jwt or role"},
				})
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.mock-vault-token",
					"lease_duration": 3600,
					"renewable":      false,
				},
			})

		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/v1/transit/encrypt/test-key"):
			encryptCalls.Add(1)
			authHeader := r.Header.Get("X-Vault-Token")
			if authHeader != "s.mock-vault-token" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"permission denied"},
				})
				return
			}

			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			pt := body["plaintext"].(string)

			// Mock ciphertext format vault:v1:<base64>
			ct := fmt.Sprintf("vault:v1:%s", base64.StdEncoding.EncodeToString([]byte("enc-"+pt)))
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"ciphertext": ct,
				},
			})

		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/v1/transit/decrypt/test-key"):
			decryptCalls.Add(1)
			authHeader := r.Header.Get("X-Vault-Token")
			if authHeader != "s.mock-vault-token" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"permission denied"},
				})
				return
			}

			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			ct := body["ciphertext"].(string)

			// Strip vault:v1:
			parts := strings.Split(ct, ":")
			raw, _ := base64.StdEncoding.DecodeString(parts[2])
			pt := strings.TrimPrefix(string(raw), "enc-")

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"plaintext": pt,
				},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	mockSpire := &mockSpireClient{
		token:       "valid-jwt-token",
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	wrapper := NewWrapper().WithCustomSpireClient(mockSpire)

	cfg, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"address":         server.URL,
		"trust_domain":    "example.org",
		"jwt_audience":    "vault",
		"jwt_auth_role":   "spire-role",
		"key_name":        "test-key",
		"disable_renewal": "true",
	}))
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, "example.org", cfg.Metadata["trust_domain"])
	require.Equal(t, "vault", cfg.Metadata["jwt_audience"])
	require.Equal(t, "spire-role", cfg.Metadata["jwt_auth_role"])

	// Verify type
	wType, err := wrapper.Type(ctx)
	require.NoError(t, err)
	require.Equal(t, Type, wType)

	// Encrypt plaintext
	plaintext := []byte("hello-openbao-spire")
	blob, err := wrapper.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	require.NotNil(t, blob)
	require.NotEmpty(t, blob.Ciphertext)
	require.Equal(t, "v1", blob.KeyInfo.KeyId)

	keyId, err := wrapper.KeyId(ctx)
	require.NoError(t, err)
	require.Equal(t, "v1", keyId)

	// Decrypt ciphertext
	decrypted, err := wrapper.Decrypt(ctx, blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	// Verify finalize
	require.NoError(t, wrapper.Finalize(ctx))

	require.Equal(t, int32(1), mockSpire.fetchCount.Load())
	require.Equal(t, int32(1), loginCalls.Load())
}
