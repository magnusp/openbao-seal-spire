//go:build integration

// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/magnusp/openbao-seal-spire/internal"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

type spireIntegrationMock struct {
	rsaKey      *rsa.PrivateKey
	trustDomain spiffeid.TrustDomain
	keyID       string
}

func newSpireIntegrationMock(td string) (*spireIntegrationMock, string, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	keyID := "test-key-id"
	jwk := jose.JSONWebKey{
		Key:       &rsaKey.PublicKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, "", err
	}

	trustDomain, err := spiffeid.TrustDomainFromString(td)
	if err != nil {
		return nil, "", err
	}

	return &spireIntegrationMock{
		rsaKey:      rsaKey,
		trustDomain: trustDomain,
		keyID:       keyID,
	}, string(jwksBytes), nil
}

func (s *spireIntegrationMock) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
	signerKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key: &jose.JSONWebKey{
			Key:   s.rsaKey,
			KeyID: s.keyID,
		},
	}

	signer, err := jose.NewSigner(signerKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	claims := jwt.Claims{
		Subject:   fmt.Sprintf("spiffe://%s/workload/openbao-seal", s.trustDomain.String()),
		Issuer:    fmt.Sprintf("https://%s", s.trustDomain.String()),
		Audience:  jwt.Audience{audience},
		Expiry:    jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
	}

	return jwt.Signed(signer).Claims(claims).Serialize()
}

func (s *spireIntegrationMock) Close() error {
	return nil
}

func TestIntegration_OpenBao_Spire_Seal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow integration test in short mode")
	}

	ctx := context.Background()

	// 1. Start live OpenBao container
	t.Log("Starting OpenBao container...")
	openbao, err := StartOpenBaoContainer(ctx)
	require.NoError(t, err)
	defer func() {
		_ = openbao.Terminate(ctx)
	}()

	client := openbao.Client

	// 2. Setup mock SPIRE JWT signer & JWKS
	trustDomain := "example.org"
	spireMock, jwksJSON, err := newSpireIntegrationMock(trustDomain)
	require.NoError(t, err)

	// 3. Configure OpenBao Transit secret engine
	t.Log("Enabling Transit secret engine...")
	err = client.Sys().MountWithContext(ctx, "transit", &api.MountInput{
		Type: "transit",
	})
	require.NoError(t, err)

	_, err = client.Logical().WriteWithContext(ctx, "transit/keys/autounseal", map[string]interface{}{
		"type": "aes256-gcm96",
	})
	require.NoError(t, err)

	// 4. Configure OpenBao JWT Auth method with SPIRE JWKS
	t.Log("Enabling JWT auth backend...")
	err = client.Sys().EnableAuthWithOptionsWithContext(ctx, "jwt", &api.EnableAuthOptions{
		Type: "jwt",
	})
	require.NoError(t, err)

	// Write JWT auth config with static JWKS
	_, err = client.Logical().WriteWithContext(ctx, "auth/jwt/config", map[string]interface{}{
		"jwt_validation_pubkeys": []string{},
		"jwks_json":              jwksJSON,
		"default_role":           "kms-role",
	})
	require.NoError(t, err)

	// Create policy granting transit encrypt/decrypt
	err = client.Sys().PutPolicyWithContext(ctx, "transit-kms-policy", `
path "transit/encrypt/autounseal" {
	capabilities = ["update"]
}
path "transit/decrypt/autounseal" {
	capabilities = ["update"]
}
`)
	require.NoError(t, err)

	// Create JWT role bound to SPIRE trust domain / subject
	_, err = client.Logical().WriteWithContext(ctx, "auth/jwt/role/kms-role", map[string]interface{}{
		"role_type":       "jwt",
		"bound_audiences": []string{"openbao"},
		"user_claim":      "sub",
		"token_policies":  []string{"transit-kms-policy"},
		"token_ttl":       "1h",
	})
	require.NoError(t, err)

	// 5. Initialize openbao-seal-spire Wrapper
	t.Log("Initializing openbao-seal-spire wrapper...")
	wrapper := internal.NewWrapper().WithCustomSpireClient(spireMock)

	cfg, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"address":         openbao.URI,
		"trust_domain":    trustDomain,
		"jwt_audience":    "openbao",
		"jwt_auth_role":   "kms-role",
		"key_name":        "autounseal",
		"mount_path":      "transit",
		"disable_renewal": "true",
	}))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// 6. Test Encrypt against live OpenBao
	plaintext := []byte("unseal-master-key-payload-data")
	blob, err := wrapper.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	require.NotNil(t, blob)
	require.NotEmpty(t, blob.Ciphertext)

	keyId, err := wrapper.KeyId(ctx)
	require.NoError(t, err)
	require.Equal(t, "autounseal", keyId)

	// 7. Test Decrypt against live OpenBao
	decrypted, err := wrapper.Decrypt(ctx, blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	t.Log("Successfully encrypted and decrypted payload using live OpenBao container and SPIRE authentication!")
}
