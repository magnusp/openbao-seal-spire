# openbao-seal-spire

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/magnusp/openbao-seal-spire/badge)](https://securityscorecards.dev/viewer/?uri=github.com/magnusp/openbao-seal-spire)

`openbao-seal-spire` is a standalone KMS & Auto-Unseal plugin for [OpenBao](https://openbao.org) that wraps the OpenBao/Vault Transit secret engine using dynamic **SPIFFE/SPIRE** authentication and **in-memory Workload API mTLS**.

Instead of requiring static root tokens or file-based certificates on disk, this plugin connects to the local **SPIRE Agent** over the SPIFFE Workload API (`agent.sock`), retrieves dynamic X.509 SVIDs for transport mTLS and JWT-SVIDs for application authentication, and talks to upstream OpenBao securely with zero disk credentials.

---

## Features

- **Zero Disk Footprint**: Private keys and certificates for mTLS stream in-memory from the SPIRE Workload API. No certificates written to container disks or volumes.
- **Dynamic Certificate & Token Lifecycle**:
  - Automatically and continuously streams rotated X.509 SVIDs and root trust bundles from SPIRE.
  - Automatically renews the OpenBao client token using `api.LifetimeWatcher`.
  - Transparently fetches fresh JWT-SVIDs and re-authenticates if the token expires or reaches maximum TTL.
- **Trust Domain & SPIFFE ID Authorization**: Enforces that received SVIDs and remote TLS servers match the expected `trust_domain` or specific `spiffe_server_id`.
- **Backward-Compatible File-Based TLS**: Allows fallback to static on-disk certificates (`tls_ca_cert`, `tls_client_cert`, `tls_client_key`) for non-SPIFFE environments with strict mutual exclusivity validation.
- **OpenBao Auto-Unseal & External Keys**:
  - Auto-unseal seal wrapping (`wrapping.Wrapper`).
  - OpenBao External Keys support (`kms.KMS`).

---

## Architecture

```
+----------------------------------------------------------------------------------------------------+
|                                      OpenBao Consumer (Main Instance)                              |
|                                                                                                    |
|  [ openbao-seal-spire Plugin ]                                                                     |
|    |                                                                                               |
|    +---> 1. Connects to Local SPIRE Agent (Workload API socket)                                   |
|    |        - Streams in-memory X.509 SVID & Trust Bundle (for mTLS)                               |
|    |        - Fetches JWT-SVID (for KMS Auth)                                                      |
|    |                                                                                               |
|    +---> 2. Connects to Upstream OpenBao over Mutual TLS (mTLS)                                    |
|    |        - Authenticates via auth/jwt/login                                                     |
|    |        - Acquires dynamic client token + renewal watcher                                      |
|    |                                                                                               |
|    +---> 3. Executes Transit Operations (encrypt / decrypt)                                        |
|             Performs Auto-Unseal & Envelope Encryption over mTLS                                   |
+----------------------------------------------------------------------------------------------------+
```

---

## Configuration

### Mode 1: Dynamic SPIFFE Workload API mTLS (Recommended)

When connecting to an HTTPS Transit server with `spiffe_socket_path` configured, dynamic SPIFFE mTLS is enabled automatically:

```hcl
plugin "kms" "transit-spire" {
  command   = "openbao-seal-spire"
  sha256sum = "<sha256-hash>"
}

seal "transit-spire" {
  # Upstream OpenBao Transit server (HTTPS)
  address             = "https://openbao-transit:8200"
  mount_path          = "transit"
  key_name            = "openbao-autounseal"

  # SPIRE & Identity parameters
  trust_domain        = "example.org"
  jwt_audience        = "openbao"
  jwt_auth_role       = "openbao-seal-role"
  jwt_auth_mount_path = "jwt"
  spiffe_socket_path  = "unix:///run/spire/sockets/agent.sock"

  # Optional: Restrict upstream Transit server to a specific SPIFFE ID
  # spiffe_server_id  = "spiffe://example.org/openbao-transit"
}
```

### Mode 2: File-Based TLS (Fallback)

For environments where upstream OpenBao uses static certificates on disk:

```hcl
seal "transit-spire" {
  address             = "https://transit.example.com:8200"
  mount_path          = "transit"
  key_name            = "openbao-autounseal"

  trust_domain        = "example.org"
  jwt_audience        = "openbao"
  jwt_auth_role       = "openbao-seal-role"
  spiffe_socket_path  = "unix:///run/spire/sockets/agent.sock"

  # Explicit file-based TLS settings
  spiffe_mtls_enabled = "false"
  tls_ca_cert         = "/etc/openbao/tls/ca.pem"
  tls_client_cert     = "/etc/openbao/tls/client.pem"
  tls_client_key      = "/etc/openbao/tls/client.key"
  tls_server_name     = "transit.example.com"
}
```

---

## Mutual Exclusivity and Precedence Rules

To prevent accidental misconfiguration or ambiguous TLS state, the plugin enforces strict validation rules:

1. **Mutual Exclusivity**:
   - Setting `spiffe_mtls_enabled = true` alongside any file-based TLS options (`tls_client_cert`, `tls_client_key`, or `tls_ca_cert`) will produce an immediate configuration error.
   - Setting `spiffe_server_id` alongside file-based TLS parameters or when `spiffe_mtls_enabled = false` will produce a configuration error.
2. **Automatic Defaults**:
   - If `spiffe_mtls_enabled` is omitted and the target `address` is `https://` without file-based TLS parameters, `spiffe_mtls_enabled` defaults to `true`.
   - If file-based TLS parameters are supplied without `spiffe_mtls_enabled`, `spiffe_mtls_enabled` defaults to `false` (file-based mode).

---

## Configuration Options

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `trust_domain` | string | **Yes** | - | SPIFFE trust domain (e.g. `example.org`) |
| `jwt_audience` | string | **Yes** | - | Target audience requested for the JWT-SVID (e.g. `openbao`) |
| `jwt_auth_role` | string | **Yes** | - | Role name on OpenBao's JWT auth backend |
| `key_name` | string | **Yes** | - | Name of the encryption key in the Transit engine |
| `spiffe_socket_path` | string | No | `SPIFFE_ENDPOINT_SOCKET` or `unix:///tmp/spire-agent/public/api.sock` | Workload API socket address |
| `spiffe_mtls_enabled` | bool | No | `true` (for `https://` without file certs) | Enable in-memory SPIFFE Workload API mTLS |
| `spiffe_server_id` | string | No | - | Expected SPIFFE ID of the upstream Transit server for mTLS authorization |
| `jwt_auth_mount_path` | string | No | `jwt` | Mount path of the JWT auth backend on upstream OpenBao |
| `address` | string | No | `https://127.0.0.1:8200` | Address of upstream Transit OpenBao server |
| `mount_path` | string | No | `transit` | Mount path of Transit secrets engine |
| `disable_renewal` | bool | No | `false` | Disable background client token renewal |
| `namespace` | string | No | - | Vault/OpenBao namespace (if applicable) |
| `tls_ca_cert` | string | No | - | Path to CA certificate (file-based TLS fallback) |
| `tls_client_cert` | string | No | - | Path to client certificate (file-based TLS fallback) |
| `tls_client_key` | string | No | - | Path to client key (file-based TLS fallback) |
| `tls_server_name` | string | No | - | Expected TLS server name (file-based TLS fallback) |
| `tls_skip_verify` | bool | No | `false` | Skip TLS certificate verification (development only) |

---

## Building and Testing

### Build Binary
```bash
make build
# Binary output: bin/openbao-seal-spire
```

### Run Fast Unit Tests (⚡ Sub-second)
Runs unit tests with in-memory mock servers without Docker:
```bash
make test-fast
# or
go test -v -short ./...
```

### Run Slow Integration Tests (🐢 Testcontainers-Go)
Runs full end-to-end integration tests with live containerized OpenBao and SPIRE:
```bash
make test-slow
# or
go test -v -tags=integration ./test/integration/...
```

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
