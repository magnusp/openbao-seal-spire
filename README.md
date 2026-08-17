# openbao-seal-spire

`openbao-seal-spire` is a standalone KMS & Auto-Unseal plugin for [OpenBao](https://openbao.org) that wraps the OpenBao/Vault Transit secret engine using dynamic **SPIFFE/SPIRE** authentication.

Instead of requiring static root or long-lived tokens in configuration files, this plugin connects to the local **SPIRE Agent** over the SPIFFE Workload API, retrieves a JWT-SVID for a configured trust domain and audience, and authenticates to upstream OpenBao via the `jwt` auth method (`auth/<mount>/login`) to obtain dynamic, automatically renewed client tokens.

---

## Features

- **No Static Secrets**: Authenticates dynamically using SPIRE Workload API JWT-SVIDs.
- **Trust Domain Verification**: Enforces that received SVIDs strictly belong to the configured `trust_domain`.
- **Automatic Token Lifecycle**:
  - Automatically renews the OpenBao client token using `api.LifetimeWatcher`.
  - Transparently fetches fresh JWT-SVIDs and re-authenticates if the token expires or reaches maximum TTL.
- **OpenBao Auto-Unseal & External Keys**:
  - Auto-unseal seal wrapping (`wrapping.Wrapper`).
  - OpenBao External Keys support (`kms.KMS`).
- **Fast and Slow Test Suite**: Separated sub-second unit tests and full containerized integration tests using Testcontainers-Go.

---

## Architecture

```
+-------------------------------------------------------------------+
|                     OpenBao Instance (Consumer)                   |
|                                                                   |
|  [ openbao-seal-spire Plugin ]                                    |
|    |                                                              |
|    +---> 1. Connects to Local SPIRE Agent (Workload API socket)  |
|    |        Fetches JWT-SVID for trust domain & audience          |
|    |                                                              |
|    +---> 2. Authenticates to Upstream OpenBao (auth/jwt/login)   |
|    |        Acquires dynamic client token + renewal watcher       |
|    |                                                              |
|    +---> 3. Executes Transit Operations (encrypt / decrypt)       |
|             Performs Auto-Unseal & Envelope Encryption            |
+-------------------------------------------------------------------+
```

---

## Configuration

In your OpenBao server configuration:

```hcl
seal "transit-spire" {
  # Upstream OpenBao Transit server
  address             = "https://transit.example.com:8200"
  mount_path          = "transit"
  key_name            = "openbao-autounseal"

  # SPIRE & JWT Auth parameters
  trust_domain        = "example.org"
  jwt_audience        = "openbao"
  jwt_auth_role       = "openbao-seal-role"
  jwt_auth_mount_path = "jwt"
  spiffe_socket_path  = "unix:///tmp/spire-agent/public/api.sock"

  # Optional TLS and renewal settings
  disable_renewal     = "false"
  tls_ca_cert         = "/etc/openbao/tls/ca.pem"
  tls_skip_verify     = "false"
}
```

### Configuration Options

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `trust_domain` | string | **Yes** | - | SPIFFE trust domain (e.g., `example.org`) |
| `jwt_audience` | string | **Yes** | - | Target audience requested for the JWT-SVID (e.g., `openbao`) |
| `jwt_auth_role` | string | **Yes** | - | Role name on OpenBao's JWT auth backend |
| `key_name` | string | **Yes** | - | Name of the encryption key in the Transit engine |
| `jwt_auth_mount_path` | string | No | `jwt` | Mount path of the JWT auth backend on upstream OpenBao |
| `spiffe_socket_path` | string | No | `SPIFFE_ENDPOINT_SOCKET` or `unix:///tmp/spire-agent/public/api.sock` | Workload API socket address |
| `address` | string | No | `https://127.0.0.1:8200` | Address of upstream Transit OpenBao server |
| `mount_path` | string | No | `transit` | Mount path of Transit secrets engine |
| `disable_renewal` | bool | No | `false` | Disable background client token renewal |
| `namespace` | string | No | - | Vault/OpenBao namespace (if applicable) |
| `tls_ca_cert` | string | No | - | Path to CA certificate for upstream server |
| `tls_client_cert` | string | No | - | Path to client certificate for mTLS |
| `tls_client_key` | string | No | - | Path to client key for mTLS |
| `tls_skip_verify` | bool | No | `false` | Skip TLS certificate verification |

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
