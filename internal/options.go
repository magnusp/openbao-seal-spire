// Copyright (c) 2026 The openbao-seal-spire Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	DefaultTransitMountPath = "transit"
	DefaultJWTAuthMountPath = "jwt"
	DefaultTransitAddress   = "https://127.0.0.1:8200"
	DefaultSpiffeSocketPath = "unix:///tmp/spire-agent/public/api.sock"

	EnvSpiffeEndpointSocket = "SPIFFE_ENDPOINT_SOCKET"

	EnvTransitWrapperMountPath   = "TRANSIT_WRAPPER_MOUNT_PATH"
	EnvVaultTransitSealMountPath = "VAULT_TRANSIT_SEAL_MOUNT_PATH"

	EnvTransitWrapperKeyName   = "TRANSIT_WRAPPER_KEY_NAME"
	EnvVaultTransitSealKeyName = "VAULT_TRANSIT_SEAL_KEY_NAME"

	EnvTransitWrapperAddr   = "TRANSIT_WRAPPER_ADDR"
	EnvVaultTransitSealAddr = "VAULT_TRANSIT_SEAL_ADDR"

	EnvTransitWrapperDisableRenewal   = "TRANSIT_WRAPPER_DISABLE_RENEWAL"
	EnvVaultTransitSealDisableRenewal = "VAULT_TRANSIT_SEAL_DISABLE_RENEWAL"

	EnvSpireTrustDomain   = "SPIRE_TRUST_DOMAIN"
	EnvSpireJwtAudience   = "SPIRE_JWT_AUDIENCE"
	EnvSpireJwtAuthRole   = "SPIRE_JWT_AUTH_ROLE"
	EnvSpireJwtAuthMount  = "SPIRE_JWT_AUTH_MOUNT_PATH"
	EnvSpireServerID      = "SPIRE_SERVER_ID"
	EnvSpireMtlsEnabled   = "SPIRE_MTLS_ENABLED"
)

// Options holds all configuration parameters for the SPIRE Transit wrapper.
type Options struct {
	*wrapping.Options

	Logger hclog.Logger

	TrustDomain      spiffeid.TrustDomain
	JwtAudience      string
	JwtAuthRole      string
	JwtAuthMountPath string
	SpiffeSocketPath string

	// SpiffeMtlsEnabled controls whether dynamic in-memory SPIFFE Workload API mTLS is used.
	SpiffeMtlsEnabled *bool
	// SpiffeServerID is the expected SPIFFE ID of the upstream Transit server for mTLS authorization.
	SpiffeServerID spiffeid.ID

	MountPath          string
	KeyName            string
	DisableRenewal     bool
	Namespace          string
	Address            string
	KeyIdPrefix        string
	TLSCaCert          string
	TLSCaCertDir       string
	TLSClientCert      string
	TLSClientKey       string
	TLSCaCertBytes     string
	TLSClientCertBytes string
	TLSClientKeyBytes  string
	TLSServerName      string
	TLSSkipVerify      bool
}

// DecodeConfigMap decodes a kms.ConfigMap into a struct using mapstructure.
func DecodeConfigMap(target any, input kms.ConfigMap) error {
	config := &mapstructure.DecoderConfig{
		Result:           target,
		WeaklyTypedInput: true,
		TagName:          "mapstructure",
	}
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return err
	}
	return decoder.Decode(input)
}

// GetOpts parses inbound wrapping.Option list and returns an Options struct.
func GetOpts(opt ...wrapping.Option) (*Options, error) {
	opts := &Options{
		MountPath:        DefaultTransitMountPath,
		JwtAuthMountPath: DefaultJWTAuthMountPath,
		Address:          DefaultTransitAddress,
	}

	var err error
	opts.Options, err = wrapping.GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	var disableRenewalRaw string
	var trustDomainRaw string
	var spiffeServerIDRaw string
	var spiffeMtlsEnabledRaw string

	for k, v := range opts.WithConfigMap {
		switch k {
		case "trust_domain":
			trustDomainRaw = v
		case "jwt_audience":
			opts.JwtAudience = v
		case "jwt_auth_role", "jwt_role":
			opts.JwtAuthRole = v
		case "jwt_auth_mount_path", "jwt_mount_path":
			opts.JwtAuthMountPath = v
		case "spiffe_socket_path", "spire_agent_address":
			opts.SpiffeSocketPath = v
		case "spiffe_server_id", "spire_server_id", "server_spiffe_id":
			spiffeServerIDRaw = v
		case "spiffe_mtls_enabled", "spire_mtls_enabled":
			spiffeMtlsEnabledRaw = v
		case "mount_path":
			opts.MountPath = v
		case "key_name":
			opts.KeyName = v
		case "disable_renewal":
			disableRenewalRaw = v
		case "namespace":
			opts.Namespace = v
		case "address":
			opts.Address = v
		case "key_id_prefix":
			opts.KeyIdPrefix = v
		case "tls_ca_cert":
			opts.TLSCaCert = v
		case "tls_ca_path":
			opts.TLSCaCertDir = v
		case "tls_client_cert":
			opts.TLSClientCert = v
		case "tls_client_key":
			opts.TLSClientKey = v
		case "tls_ca_cert_bytes":
			opts.TLSCaCertBytes = v
		case "tls_client_cert_bytes":
			opts.TLSClientCertBytes = v
		case "tls_client_key_bytes":
			opts.TLSClientKeyBytes = v
		case "tls_server_name":
			opts.TLSServerName = v
		case "tls_skip_verify":
			opts.TLSSkipVerify, err = strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("invalid boolean value for tls_skip_verify: %w", err)
			}
		}
	}

	// Environment variable fallbacks if env vars are allowed
	if !opts.WithDisallowEnvVars {
		if trustDomainRaw == "" {
			trustDomainRaw = os.Getenv(EnvSpireTrustDomain)
		}
		if opts.JwtAudience == "" {
			opts.JwtAudience = os.Getenv(EnvSpireJwtAudience)
		}
		if opts.JwtAuthRole == "" {
			opts.JwtAuthRole = os.Getenv(EnvSpireJwtAuthRole)
		}
		if opts.JwtAuthMountPath == DefaultJWTAuthMountPath && os.Getenv(EnvSpireJwtAuthMount) != "" {
			opts.JwtAuthMountPath = os.Getenv(EnvSpireJwtAuthMount)
		}
		if opts.SpiffeSocketPath == "" {
			if envSocket := os.Getenv(EnvSpiffeEndpointSocket); envSocket != "" {
				opts.SpiffeSocketPath = envSocket
			}
		}
		if spiffeServerIDRaw == "" {
			spiffeServerIDRaw = os.Getenv(EnvSpireServerID)
		}
		if spiffeMtlsEnabledRaw == "" {
			spiffeMtlsEnabledRaw = os.Getenv(EnvSpireMtlsEnabled)
		}
		if opts.MountPath == DefaultTransitMountPath {
			if envMount := os.Getenv(EnvTransitWrapperMountPath); envMount != "" {
				opts.MountPath = envMount
			} else if envMount := os.Getenv(EnvVaultTransitSealMountPath); envMount != "" {
				opts.MountPath = envMount
			}
		}
		if opts.KeyName == "" {
			if envKey := os.Getenv(EnvTransitWrapperKeyName); envKey != "" {
				opts.KeyName = envKey
			} else if envKey := os.Getenv(EnvVaultTransitSealKeyName); envKey != "" {
				opts.KeyName = envKey
			}
		}
		if opts.Address == DefaultTransitAddress {
			if envAddr := os.Getenv(EnvTransitWrapperAddr); envAddr != "" {
				opts.Address = envAddr
			} else if envAddr := os.Getenv(EnvVaultTransitSealAddr); envAddr != "" {
				opts.Address = envAddr
			}
		}
		if disableRenewalRaw == "" {
			if envRen := os.Getenv(EnvTransitWrapperDisableRenewal); envRen != "" {
				disableRenewalRaw = envRen
			} else if envRen := os.Getenv(EnvVaultTransitSealDisableRenewal); envRen != "" {
				disableRenewalRaw = envRen
			}
		}
		if opts.Namespace == "" {
			if envNs := os.Getenv("VAULT_NAMESPACE"); envNs != "" {
				opts.Namespace = envNs
			}
		}
	}

	if opts.SpiffeSocketPath == "" {
		opts.SpiffeSocketPath = DefaultSpiffeSocketPath
	}

	if disableRenewalRaw != "" {
		opts.DisableRenewal, err = strconv.ParseBool(disableRenewalRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid boolean value for disable_renewal: %w", err)
		}
	}

	if spiffeMtlsEnabledRaw != "" {
		b, err := strconv.ParseBool(spiffeMtlsEnabledRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid boolean value for spiffe_mtls_enabled: %w", err)
		}
		opts.SpiffeMtlsEnabled = &b
	}

	// Validate required parameters
	if trustDomainRaw == "" {
		return nil, errors.New("trust_domain is required")
	}
	td, err := spiffeid.TrustDomainFromString(trustDomainRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid trust_domain %q: %w", trustDomainRaw, err)
	}
	opts.TrustDomain = td

	if spiffeServerIDRaw != "" {
		serverID, err := spiffeid.FromString(spiffeServerIDRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid spiffe_server_id %q: %w", spiffeServerIDRaw, err)
		}
		opts.SpiffeServerID = serverID
	}

	if opts.JwtAudience == "" {
		return nil, errors.New("jwt_audience is required")
	}
	if opts.JwtAuthRole == "" {
		return nil, errors.New("jwt_auth_role is required")
	}
	if opts.KeyName == "" {
		return nil, errors.New("key_name is required")
	}

	hasFileClientCert := (opts.TLSClientCert != "" || opts.TLSClientCertBytes != "")
	hasFileClientKey := (opts.TLSClientKey != "" || opts.TLSClientKeyBytes != "")
	hasFileCA := (opts.TLSCaCert != "" || opts.TLSCaCertDir != "" || opts.TLSCaCertBytes != "")

	// Enforce mutual exclusivity between file-based TLS and SPIFFE dynamic Workload API mTLS
	if opts.SpiffeMtlsEnabled != nil && *opts.SpiffeMtlsEnabled {
		if hasFileClientCert || hasFileClientKey {
			return nil, errors.New("cannot configure file-based client certificate/key ('tls_client_cert'/'tls_client_key') when SPIFFE dynamic mTLS ('spiffe_mtls_enabled') is enabled")
		}
		if hasFileCA {
			return nil, errors.New("cannot configure file-based CA certificate ('tls_ca_cert'/'tls_ca_path') when SPIFFE dynamic mTLS ('spiffe_mtls_enabled') is enabled; trust bundle is streamed dynamically from SPIRE")
		}
	} else if opts.SpiffeMtlsEnabled != nil && !*opts.SpiffeMtlsEnabled {
		if !opts.SpiffeServerID.IsZero() {
			return nil, errors.New("cannot configure 'spiffe_server_id' when SPIFFE dynamic mTLS ('spiffe_mtls_enabled') is explicitly disabled")
		}
	} else {
		// When spiffe_mtls_enabled is not explicitly specified:
		if hasFileClientCert || hasFileClientKey || hasFileCA {
			if !opts.SpiffeServerID.IsZero() {
				return nil, errors.New("cannot configure 'spiffe_server_id' alongside file-based TLS parameters ('tls_client_cert'/'tls_ca_cert')")
			}
			f := false
			opts.SpiffeMtlsEnabled = &f
		} else if strings.HasPrefix(opts.Address, "https://") {
			t := true
			opts.SpiffeMtlsEnabled = &t
		} else {
			f := false
			opts.SpiffeMtlsEnabled = &f
		}
	}

	return opts, nil
}
