// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestKMS_MockTransitServer(t *testing.T) {
	ctx := context.Background()

	// Generate a test RSA key pair for public key and signing responses
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubASN1, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}))

	var loginCalls atomic.Int32
	var encryptCalls atomic.Int32
	var decryptCalls atomic.Int32
	var signCalls atomic.Int32
	var verifyCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/v1/auth/jwt/login"):
			loginCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.mock-vault-token",
					"lease_duration": 3600,
					"renewable":      false,
				},
			})

		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/v1/transit/encrypt/kms-key"):
			encryptCalls.Add(1)
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			pt := body["plaintext"].(string)

			ct := fmt.Sprintf("vault:v1:%s", base64.StdEncoding.EncodeToString([]byte("ct-"+pt)))
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"ciphertext": ct,
				},
			})

		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/v1/transit/decrypt/kms-key"):
			decryptCalls.Add(1)
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			ct := body["ciphertext"].(string)

			parts := strings.Split(ct, ":")
			raw, _ := base64.StdEncoding.DecodeString(parts[2])
			pt := strings.TrimPrefix(string(raw), "ct-")

			rawPT, _ := base64.StdEncoding.DecodeString(pt)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"plaintext": base64.StdEncoding.EncodeToString(rawPT),
				},
			})

		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/v1/transit/sign/kms-key"):
			signCalls.Add(1)
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)

			sig := fmt.Sprintf("vault:v1:%s", base64.StdEncoding.EncodeToString([]byte("mock-sig")))
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"signature": sig,
				},
			})

		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/v1/transit/verify/kms-key"):
			verifyCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"valid": true,
				},
			})

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v1/transit/keys/kms-key"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": map[string]interface{}{
						"1": map[string]interface{}{
							"public_key": pubPEM,
						},
					},
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

	kmsInst := &spireTransitKMS{
		spireClient: mockSpire,
	}

	err = kmsInst.Open(ctx, &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"address":         server.URL,
			"trust_domain":    "example.org",
			"jwt_audience":    "vault",
			"jwt_auth_role":   "spire-role",
			"disable_renewal": true,
		},
	})
	require.NoError(t, err)

	key, err := kmsInst.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{
			"name":    "kms-key",
			"version": uint64(1),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, key)

	// Test Encrypt / Decrypt
	plaintext := []byte("secret-payload")
	ct, err := key.Encrypt(ctx, &kms.CipherOptions{Data: plaintext})
	require.NoError(t, err)
	require.NotEmpty(t, ct)

	dec, err := key.Decrypt(ctx, &kms.CipherOptions{Data: ct})
	require.NoError(t, err)
	require.Equal(t, plaintext, dec)

	// Test Sign / Verify
	sig, err := key.Sign(ctx, &kms.SignOptions{
		Data:       []byte("message-to-sign"),
		SignerOpts: crypto.SHA256,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("mock-sig"), sig)

	err = key.Verify(ctx, &kms.VerifyOptions{
		Data:       []byte("message-to-sign"),
		Signature:  sig,
		SignerOpts: crypto.SHA256,
	})
	require.NoError(t, err)

	// Test Public Key retrieval
	pubKey, err := key.ExportPublic(ctx)
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	require.NoError(t, kmsInst.Close(ctx))
	require.Equal(t, int32(1), loginCalls.Load())
	require.Equal(t, int32(1), encryptCalls.Load())
	require.Equal(t, int32(1), decryptCalls.Load())
	require.Equal(t, int32(1), signCalls.Load())
	require.Equal(t, int32(1), verifyCalls.Load())
}
