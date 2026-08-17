# OpenBao SPIRE KMS Docker Compose Example (Zero-Disk Dynamic mTLS)

This example demonstrates an end-to-end deployment of **OpenBao Auto-Unseal with SPIRE authentication**, secured with in-memory **SPIFFE Workload API Mutual TLS (mTLS)** and JWT authentication.

---

## Architecture Overview

```
+----------------------------------------------------------------------------------------------------+
|                                         Docker Compose Network                                     |
|                                                                                                    |
|  +---------------------+                                             +--------------------------+  |
|  |   openbao-transit   |                                             |       spire-server       |  |
|  |  (PKI Root & KMS)   |<=========== mTLS & Cert Auth (CSR) =========|   (UpstreamAuthority:    |  |
|  |  Port: 8200         |                                             |      OpenBao PKI)        |  |
|  |  (mTLS Listener)    |                                             +------------+-------------+  |
|  +----+-----------+----+                                                          |                |
|       |           |                                                               |                |
|  Root CA PKI      \================= JWT Validation JWKS =========================/                |
|  Signs Int CA                                                                     |                |
|       v                                                                           | Node Attest    |
|       \======================================================\                    v                |
|                                                               \======+--------------------------+  |
|                                                                      |       spire-agent        |  |
|                                                                      |  (/run/spire/sockets/    |  |
|                                                                      |      agent.sock)         |  |
|                                                                      +------------+-------------+  |
|                                                                                   |                |
|                                                                             SPIFFE Workload API    |
|                                                                            - In-Memory X.509 SVID  |
|                                                                            - In-Memory JWT-SVID    |
|                                                                                   v                |
|                                    1. Dynamic mTLS (Zero-Disk X.509 SVID) +---------------------+  |
|                                    2. Auth: SPIRE JWT-SVID                |   openbao-consumer  |  |
|                                    <======================================|   Port: 8201        |  |
|                                    3. Envelope Encryption via Transit     |   (transit-spire)   |  |
|                                                                           +---------------------+  |
+----------------------------------------------------------------------------------------------------+
```

### Security Highlights

1. **Zero-Disk Client Identity**:
   - `openbao-consumer` does **not** store any client certificates or private keys on disk.
   - The plugin establishes an in-memory X.509 watcher via `/run/spire/sockets/agent.sock` using `go-spiffe/v2`'s `X509Source`.
   - Rotations happen continuously and transparently in memory before expiration.
2. **Dual-Layer SPIFFE Security**:
   - **Transport Layer**: mTLS handshake verified against the trust domain `example.org` and server SPIFFE ID `spiffe://example.org/openbao-transit`.
   - **Application Layer**: JWT-SVID passed to `auth/jwt/login` for KMS encryption and decryption policies.

---

## Directory Layout

```text
examples/
├── compose.yml           # Compose services using official upstream images
├── Dockerfile            # Multi-stage build (setup & consumer plugin image)
├── setup.sh              # Single init & bootstrap orchestrator script
├── README.md             # Architecture & step-by-step verification guide
└── config/
    ├── server.conf       # SPIRE Server configuration
    ├── agent.conf        # SPIRE Agent configuration
    ├── transit.hcl       # Upstream Transit KMS & PKI server configuration
    └── consumer.hcl      # Main OpenBao consumer instance configuration
```

---

## Quick Start

### 1. Start the Environment

From the repository root:

```bash
docker compose -f examples/compose.yml up --build -d
```

### 2. Verify Service Status

Check container status:

```bash
docker compose -f examples/compose.yml ps
```

### 3. Verify mTLS Enforcement on Transit Server

Attempting to connect to the Transit server without a client certificate is rejected at the TLS handshake:

```bash
curl -k https://127.0.0.1:8200/v1/sys/seal-status
# Fails with SSL/TLS alert bad certificate
```

### 4. Check Initial Seal Status of Consumer

The consumer instance starts sealed and uninitialized:

```bash
export BAO_ADDR="http://127.0.0.1:8201"
bao status
```

### 5. Initialize Consumer Instance to Test Auto-Unseal

Initialize the consumer instance with recovery shares:

```bash
bao operator init -recovery-shares=1 -recovery-threshold=1
```

Check the seal status again to confirm auto-unseal succeeded over dynamic SPIFFE mTLS:

```bash
bao status
```

Output:
```text
Key                      Value
---                      -----
Recovery Seal Type       shamir
Initialized              true
Sealed                   false
Total Recovery Shares    1
Threshold                1
Unseal Lower Bound       1
Unseal Progress          0
Unseal Nonce             n/a
Seal Type                transit-spire
...
```

---

## Clean Up

To tear down the containers and clean up volumes:

```bash
docker compose -f examples/compose.yml down -v
```
