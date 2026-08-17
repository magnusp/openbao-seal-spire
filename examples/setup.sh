#!/bin/sh
set -eu

SOCKET_PATH="/tmp/spire-server/private/api.sock"
TRANSIT_ADDR="https://openbao-transit:8200"

echo "========================================================"
echo "  Bootstrapping SPIRE and OpenBao Transit KMS"
echo "========================================================"

# 1. Generate Root CA, Server Certs, and Client Certs
echo "[1/6] Generating Root CA and mTLS Certificates..."
mkdir -p /openbao/tls /openbao/config /opt/spire/conf /tmp/tls

# Root CA
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /openbao/tls/ca.key \
  -out /openbao/tls/ca.crt \
  -days 3650 \
  -subj "/CN=example.org Root CA"

# OpenBao Transit Server Cert (with SANs)
cat << 'EOF' > /tmp/tls/transit_ext.cnf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = openbao-transit

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = openbao-transit
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -newkey rsa:2048 -nodes \
  -keyout /openbao/tls/transit-server.key \
  -out /tmp/tls/transit-server.csr \
  -config /tmp/tls/transit_ext.cnf

openssl x509 -req -in /tmp/tls/transit-server.csr \
  -CA /openbao/tls/ca.crt \
  -CAkey /openbao/tls/ca.key \
  -CAcreateserial \
  -out /openbao/tls/transit-server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile /tmp/tls/transit_ext.cnf

# Admin Client Cert (for init-setup)
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /openbao/tls/admin-client.key \
  -out /tmp/tls/admin-client.csr \
  -subj "/CN=admin"

openssl x509 -req -in /tmp/tls/admin-client.csr \
  -CA /openbao/tls/ca.crt \
  -CAkey /openbao/tls/ca.key \
  -CAcreateserial \
  -out /openbao/tls/admin-client.crt \
  -days 365

# SPIRE Server Client Cert
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /openbao/tls/spire-client.key \
  -out /tmp/tls/spire-client.csr \
  -subj "/CN=spire-server"

openssl x509 -req -in /tmp/tls/spire-client.csr \
  -CA /openbao/tls/ca.crt \
  -CAkey /openbao/tls/ca.key \
  -CAcreateserial \
  -out /openbao/tls/spire-client.crt \
  -days 365

# OpenBao Consumer Client Cert
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /openbao/tls/consumer-client.key \
  -out /tmp/tls/consumer-client.csr \
  -subj "/CN=openbao-consumer"

openssl x509 -req -in /tmp/tls/consumer-client.csr \
  -CA /openbao/tls/ca.crt \
  -CAkey /openbao/tls/ca.key \
  -CAcreateserial \
  -out /openbao/tls/consumer-client.crt \
  -days 365

chmod 644 /openbao/tls/*.crt /openbao/tls/*.key || true

# 2. Template Configuration Files
echo "[2/6] Templating configuration files..."
cp /config-src/transit.hcl /openbao/config/transit.hcl
cp /config-src/server.conf /opt/spire/conf/server.conf

PLUGIN_SHA256=$(sha256sum /openbao-seal-spire | awk '{print $1}')
sed "s/__PLUGIN_SHA256__/$PLUGIN_SHA256/g" /config-src/consumer.hcl > /openbao/config/consumer.hcl

# Helper for curl over mTLS
curl_mtls() {
  curl -s --cacert /openbao/tls/ca.crt \
    --cert /openbao/tls/admin-client.crt \
    --key /openbao/tls/admin-client.key \
    "$@"
}

# 3. Wait for OpenBao Transit, Initialize and Unseal
echo "[3/6] Waiting for OpenBao Transit server..."
until curl_mtls "$TRANSIT_ADDR/v1/sys/seal-status" > /dev/null 2>&1; do
  sleep 1
done

echo "      Initializing and unsealing OpenBao Transit..."
INIT_RES=$(curl_mtls -X POST "$TRANSIT_ADDR/v1/sys/init" \
  -d '{"secret_shares": 1, "secret_threshold": 1}')

UNSEAL_KEY=$(echo "$INIT_RES" | jq -r '.keys[0]')
ROOT_TOKEN=$(echo "$INIT_RES" | jq -r '.root_token')

curl_mtls -X POST "$TRANSIT_ADDR/v1/sys/unseal" \
  -d "{\"key\": \"$UNSEAL_KEY\"}" > /dev/null

# 4. Configure PKI, Cert Auth, Transit KMS on Transit server
echo "[4/6] Configuring PKI Root CA, Cert Auth, and Transit KMS..."

# Mount PKI and load Root CA
curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/sys/mounts/pki" \
  -d '{"type":"pki", "config":{"max_lease_ttl":"8760h"}}' || true

PEM_BUNDLE=$(cat /openbao/tls/ca.crt /openbao/tls/ca.key | awk '{printf "%s\\n", $0}')
curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/pki/config/ca" \
  -d "{\"pem_bundle\": \"$PEM_BUNDLE\"}" || true

curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/pki/config/urls" \
  -d '{
    "issuing_certificates": ["https://openbao-transit:8200/v1/pki/ca"],
    "crl_distribution_points": ["https://openbao-transit:8200/v1/pki/crl"]
  }' || true

# TLS Certificate Auth method for SPIRE Server
curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/sys/auth/cert" \
  -d '{"type":"cert"}' || true

curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X PUT "$TRANSIT_ADDR/v1/sys/policies/acl/spire-pki-policy" \
  -d '{"policy":"path \"pki/root/sign-intermediate\" {\n  capabilities = [\"update\"]\n}\n"}'

SPIRE_CERT_PEM=$(awk '{printf "%s\\n", $0}' /openbao/tls/spire-client.crt)
curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/auth/cert/certs/spire" \
  -d "{\"certificate\": \"$SPIRE_CERT_PEM\", \"token_policies\": [\"spire-pki-policy\"], \"token_ttl\": \"1h\"}"

# Transit Secrets Engine & Auto-Unseal Key
curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/sys/mounts/transit" \
  -d '{"type":"transit"}' || true

curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/transit/keys/autounseal" \
  -d '{"type":"aes256-gcm96"}' || true

curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/sys/auth/jwt" \
  -d '{"type":"jwt"}' || true

# 5. Wait for SPIRE Server to connect and initialize
echo "[5/6] Waiting for SPIRE Server..."
until spire-server healthcheck -socketPath "$SOCKET_PATH" > /dev/null 2>&1; do
  sleep 1
done
echo "      SPIRE Server is healthy."

# 6. Generate Join Token, Register Workloads, and Export JWT Bundle
echo "[6/6] Generating Join Token and Registering Workloads..."
TOKEN_OUTPUT=$(spire-server token generate -socketPath "$SOCKET_PATH" -spiffeID "spiffe://example.org/agent-node")
JOIN_TOKEN=$(echo "$TOKEN_OUTPUT" | awk '/Token:/ {print $2}')
if [ -z "$JOIN_TOKEN" ]; then
  JOIN_TOKEN=$(echo "$TOKEN_OUTPUT" | awk '{print $2}')
fi

sed "s/__JOIN_TOKEN__/$JOIN_TOKEN/g" /config-src/agent.conf > /opt/spire/conf/agent.conf

spire-server entry create -socketPath "$SOCKET_PATH" \
  -spiffeID "spiffe://example.org/openbao-consumer" \
  -parentID "spiffe://example.org/agent-node" \
  -selector "unix:uid:100" || true

spire-server entry create -socketPath "$SOCKET_PATH" \
  -spiffeID "spiffe://example.org/openbao-consumer" \
  -parentID "spiffe://example.org/agent-node" \
  -selector "unix:uid:0" || true

PUB_KEYS_JSON=$(spire-server bundle show -socketPath "$SOCKET_PATH" -output json | jq '[.jwt_authorities[].public_key | "-----BEGIN PUBLIC KEY-----\n" + . + "\n-----END PUBLIC KEY-----"]')

curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/auth/jwt/config" \
  -d "{\"jwt_validation_pubkeys\": $PUB_KEYS_JSON, \"default_role\":\"kms-role\"}"

curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X PUT "$TRANSIT_ADDR/v1/sys/policies/acl/transit-kms-policy" \
  -d '{"policy":"path \"transit/encrypt/autounseal\" {\n  capabilities = [\"update\"]\n}\npath \"transit/decrypt/autounseal\" {\n  capabilities = [\"update\"]\n}\n"}'

curl_mtls -H "X-Vault-Token: $ROOT_TOKEN" \
  -X POST "$TRANSIT_ADDR/v1/auth/jwt/role/kms-role" \
  -d '{
    "role_type": "jwt",
    "bound_audiences": ["openbao"],
    "user_claim": "sub",
    "token_policies": ["transit-kms-policy"],
    "token_ttl": "1h"
  }'

echo "========================================================"
echo "  Setup Complete! All services bootstrapped."
echo "========================================================"
