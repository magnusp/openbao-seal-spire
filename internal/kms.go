// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"cmp"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/openbao/go-kms-wrapping/v2/kms"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/api/v2"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var ErrPrehashingDisabled = errors.New("pre-hashing is disabled")

// SensitiveKMSFields are fields accepted by Open() that should be censored.
var SensitiveKMSFields = []string{}

var hash2transit = map[crypto.Hash]string{
	crypto.SHA1:     "sha1",
	crypto.SHA224:   "sha2-224",
	crypto.SHA256:   "sha2-256",
	crypto.SHA384:   "sha2-384",
	crypto.SHA512:   "sha2-512",
	crypto.SHA3_224: "sha3-224",
	crypto.SHA3_256: "sha3-256",
	crypto.SHA3_384: "sha3-384",
	crypto.SHA3_512: "sha3-512",
}

// NewKMS returns a new KMS implementation that authenticates to OpenBao Transit via SPIRE.
func NewKMS() kms.KMS {
	return &spireTransitKMS{}
}

type spireTransitKMS struct {
	kms.UnimplementedKMS

	transitClient *SpireTransitClient
	spireClient   SpireClient
	mount         string
}

func (k *spireTransitKMS) Open(ctx context.Context, opts *kms.OpenOptions) error {
	var cfg struct {
		Address          string `mapstructure:"address"`
		Namespace        string `mapstructure:"namespace"`
		MountPath        string `mapstructure:"mount_path"`
		DisableRenewal   bool   `mapstructure:"disable_renewal"`
		TrustDomain      string `mapstructure:"trust_domain"`
		JwtAudience      string `mapstructure:"jwt_audience"`
		JwtAuthRole      string `mapstructure:"jwt_auth_role"`
		JwtAuthMountPath string `mapstructure:"jwt_auth_mount_path"`
		SpiffeSocketPath string `mapstructure:"spiffe_socket_path"`

		TLSServerName      string `mapstructure:"tls_server_name"`
		TLSSkipVerify      bool   `mapstructure:"tls_skip_verify"`
		TLSCACertBytes     string `mapstructure:"tls_ca_cert_bytes"`
		TLSClientCertBytes string `mapstructure:"tls_client_cert_bytes"`
		TLSClientKeyBytes  string `mapstructure:"tls_client_key_bytes"`
	}

	if err := DecodeConfigMap(&cfg, opts.ConfigMap); err != nil {
		return err
	}

	if cfg.TrustDomain == "" {
		return errors.New("missing required parameter 'trust_domain'")
	}
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		return fmt.Errorf("invalid trust_domain %q: %w", cfg.TrustDomain, err)
	}

	if cfg.JwtAudience == "" {
		return errors.New("missing required parameter 'jwt_audience'")
	}
	if cfg.JwtAuthRole == "" {
		return errors.New("missing required parameter 'jwt_auth_role'")
	}

	optStruct := &Options{
		Options: &wrapping.Options{
			WithDisallowEnvVars: !opts.AllowEnvironment,
		},
		Logger:             opts.Logger,
		TrustDomain:        td,
		JwtAudience:        cfg.JwtAudience,
		JwtAuthRole:        cfg.JwtAuthRole,
		JwtAuthMountPath:   cmp.Or(cfg.JwtAuthMountPath, DefaultJWTAuthMountPath),
		SpiffeSocketPath:   cmp.Or(cfg.SpiffeSocketPath, DefaultSpiffeSocketPath),
		MountPath:          cmp.Or(cfg.MountPath, DefaultTransitMountPath),
		Address:            cmp.Or(cfg.Address, DefaultTransitAddress),
		Namespace:          cfg.Namespace,
		DisableRenewal:     cfg.DisableRenewal,
		TLSServerName:      cfg.TLSServerName,
		TLSSkipVerify:      cfg.TLSSkipVerify,
		TLSCaCertBytes:     cfg.TLSCACertBytes,
		TLSClientCertBytes: cfg.TLSClientCertBytes,
		TLSClientKeyBytes:  cfg.TLSClientKeyBytes,
	}

	if k.spireClient == nil {
		var err error
		k.spireClient, err = NewSpireClient(ctx, optStruct.SpiffeSocketPath, optStruct.TrustDomain)
		if err != nil {
			return err
		}
	}

	client, _, err := NewSpireTransitClient(ctx, optStruct, k.spireClient)
	if err != nil {
		return err
	}

	k.transitClient = client
	k.mount = optStruct.MountPath
	return nil
}

func (k *spireTransitKMS) Close(context.Context) error {
	if k.transitClient != nil {
		k.transitClient.Close()
	}
	return nil
}

func (k *spireTransitKMS) GetKey(_ context.Context, opts *kms.KeyOptions) (kms.Key, error) {
	var cfg struct {
		Name              string `mapstructure:"name"`
		Version           uint64 `mapstructure:"version"`
		DisablePrehashing bool   `mapstructure:"disable_prehashing"`
	}

	if err := DecodeConfigMap(&cfg, opts.ConfigMap); err != nil {
		return nil, err
	}

	switch {
	case cfg.Name == "":
		return nil, errors.New("missing required parameter 'name'")
	case cfg.Version <= 0:
		return nil, errors.New("missing required parameter 'version'")
	}

	return &spireTransitKey{
		client:            k.transitClient.GetApiClient(),
		mount:             k.mount,
		name:              cfg.Name,
		version:           cfg.Version,
		disablePrehashing: cfg.DisablePrehashing,
	}, nil
}

type spireTransitKey struct {
	kms.UnimplementedKey

	client *api.Client

	mount   string
	name    string
	version uint64

	disablePrehashing bool
}

func (k *spireTransitKey) Encrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	data := map[string]any{
		"plaintext":   base64.StdEncoding.EncodeToString(opts.Data),
		"key_version": strconv.FormatUint(k.version, 10),
	}
	if len(opts.AAD) != 0 {
		data["associated_data"] = base64.StdEncoding.EncodeToString(opts.AAD)
	}

	resp, err := k.client.Logical().WriteWithContext(
		ctx, path.Join(k.mount, "encrypt", k.name), data,
	)
	if err != nil {
		return nil, err
	}

	ciphertext, ok := resp.Data["ciphertext"].(string)
	if !ok {
		return nil, errors.New("expected response to include 'ciphertext' field of type string")
	}
	parts := strings.SplitN(ciphertext, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected ciphertext to split into 3 parts, got %d", len(parts))
	}
	out, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	version, err := strconv.ParseUint(parts[1][1:], 10, 64)
	switch {
	case err != nil:
		return nil, fmt.Errorf("parse key version: %w", err)
	case version != k.version:
		return nil, fmt.Errorf("expected used key version to match configured version %d, got %d", k.version, version)
	}
	return out, nil
}

func (k *spireTransitKey) Decrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	data := map[string]any{
		"ciphertext": fmt.Sprintf("vault:v%d:%s",
			k.version, base64.StdEncoding.EncodeToString(opts.Data)),
	}
	if len(opts.AAD) != 0 {
		data["associated_data"] = base64.StdEncoding.EncodeToString(opts.AAD)
	}

	resp, err := k.client.Logical().WriteWithContext(
		ctx, path.Join(k.mount, "decrypt", k.name), data,
	)
	if err != nil {
		return nil, err
	}

	plaintext, ok := resp.Data["plaintext"].(string)
	if !ok {
		return nil, errors.New("expected response to include 'plaintext' field of type string")
	}
	return base64.StdEncoding.DecodeString(plaintext)
}

func (k *spireTransitKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	hash := opts.HashFunc()
	if opts.Prehashed && hash != crypto.Hash(0) && k.disablePrehashing {
		return nil, ErrPrehashingDisabled
	}

	data := map[string]any{"key_version": strconv.FormatUint(k.version, 10)}
	if transitHash, ok := hash2transit[hash]; ok {
		data["hash_algorithm"] = transitHash
	} else if hash != crypto.Hash(0) {
		return nil, fmt.Errorf("unsupported hash function: %s", hash)
	}

	if !opts.Prehashed && hash != crypto.Hash(0) && !k.disablePrehashing {
		h := hash.New()
		if _, err := h.Write(opts.Data); err != nil {
			return nil, fmt.Errorf("hash message: %w", err)
		}
		data["input"] = base64.StdEncoding.EncodeToString(h.Sum(nil))
		data["prehashed"] = true
	} else {
		data["input"] = base64.StdEncoding.EncodeToString(opts.Data)
		data["prehashed"] = opts.Prehashed && hash != crypto.Hash(0)
	}

	switch opt := opts.SignerOpts.(type) {
	case *rsa.PSSOptions:
		switch opt.SaltLength {
		case rsa.PSSSaltLengthAuto:
			data["salt_length"] = "auto"
		case rsa.PSSSaltLengthEqualsHash:
			data["salt_length"] = "hash"
		default:
			data["salt_length"] = opt.SaltLength
		}
	case *ed25519.Options:
		if hash != crypto.Hash(0) {
			return nil, errors.New("pre-hashed Ed25519 variants are not supported")
		}
	default:
		data["signature_algorithm"] = "pkcs1v15"
	}

	resp, err := k.client.Logical().WriteWithContext(
		ctx, path.Join(k.mount, "sign", k.name), data,
	)
	if err != nil {
		return nil, err
	}

	sig, ok := resp.Data["signature"].(string)
	if !ok {
		return nil, errors.New("expected response to include 'signature' field of type string")
	}
	parts := strings.SplitN(sig, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected signature to split into 3 parts, got %d", len(parts))
	}
	return base64.StdEncoding.DecodeString(parts[2])
}

func (k *spireTransitKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	hash := opts.HashFunc()
	if opts.Prehashed && hash != crypto.Hash(0) && k.disablePrehashing {
		return ErrPrehashingDisabled
	}

	data := map[string]any{
		"signature": fmt.Sprintf("vault:v%d:%s",
			k.version, base64.StdEncoding.EncodeToString(opts.Signature)),
	}

	if transitHash, ok := hash2transit[hash]; ok {
		data["hash_algorithm"] = transitHash
	} else if hash != crypto.Hash(0) {
		return fmt.Errorf("unsupported hash function: %s", hash)
	}

	if !opts.Prehashed && hash != crypto.Hash(0) && !k.disablePrehashing {
		h := hash.New()
		if _, err := h.Write(opts.Data); err != nil {
			return fmt.Errorf("hash message: %w", err)
		}
		data["input"] = base64.StdEncoding.EncodeToString(h.Sum(nil))
		data["prehashed"] = true
	} else {
		data["input"] = base64.StdEncoding.EncodeToString(opts.Data)
		data["prehashed"] = opts.Prehashed && hash != crypto.Hash(0)
	}

	switch opt := opts.SignerOpts.(type) {
	case *rsa.PSSOptions:
		switch opt.SaltLength {
		case rsa.PSSSaltLengthAuto:
			data["salt_length"] = "auto"
		case rsa.PSSSaltLengthEqualsHash:
			data["salt_length"] = "hash"
		default:
			data["salt_length"] = opt.SaltLength
		}
	case *ed25519.Options:
		if hash != crypto.Hash(0) {
			return errors.New("pre-hashed Ed25519 variants are not supported")
		}
	default:
		data["signature_algorithm"] = "pkcs1v15"
	}

	resp, err := k.client.Logical().WriteWithContext(
		ctx, path.Join(k.mount, "verify", k.name), data,
	)
	if err != nil {
		return err
	}

	valid, ok := resp.Data["valid"].(bool)
	if !ok {
		return errors.New("expected response to include 'valid' field of type bool")
	}
	if !valid {
		return kms.ErrInvalidSignature
	}
	return nil
}

func (k *spireTransitKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	resp, err := k.client.Logical().ReadWithContext(
		ctx, path.Join(k.mount, "keys", k.name),
	)
	if err != nil {
		return nil, err
	}

	keys, ok := resp.Data["keys"].(map[string]any)
	if !ok {
		return nil, errors.New("expected response to include 'keys' field of type map")
	}

	keyData, ok := keys[strconv.FormatUint(k.version, 10)].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("key version %d not found in transit response", k.version)
	}

	pubKeyPEM, ok := keyData["public_key"].(string)
	if !ok || pubKeyPEM == "" {
		return nil, errors.New("public_key not found in key data")
	}

	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing public key")
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}
