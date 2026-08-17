# OpenBao SPIRE KMS Docker Compose Example

This example demonstrates an end-to-end deployment of **OpenBao Auto-Unseal with SPIRE authentication**, secured with **Mutual TLS (mTLS)** between OpenBao instances and SPIRE. The upstream OpenBao instance also serves as the **PKI Root CA** for the SPIRE topology.

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
|                                                                              Workload API          |
|                                                                               (JWT-SVID)           |
|                                                                                   v                |
|                                    1. Secure Channel: Mutual TLS (mTLS) +-----------------------+  |
|                                    2. Auth: SPIRE JWT-SVID              |    openbao-consumer   |  |
|                                    <====================================|    Port: 8201         |  |
|                                    3. Envelope Encryption via Transit   |    (transit-spire)    |  |
|                                                                         +-----------------------+  |
+----------------------------------------------------------------------------------------------------+
```

### Directory Layout

The example is organized compactly into:

```text
examples/
├── compose.yml           # Complete Compose stack definition
├── Dockerfile            # Multi-stage build (setup & consumer plugin image)
├── setup.sh              # Single init & bootstrap orchestrator script
├── README.md             # Architecture and testing guide
└── config/
    ├── server.conf       # SPIRE Server configuration
    ├── agent.conf        # SPIRE Agent configuration
    ├── transit.hcl       # Upstream OpenBao KMS & PKI server configuration
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

Check the seal status again to confirm auto-unseal succeeded over mTLS:

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
