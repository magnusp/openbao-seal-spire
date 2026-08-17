plugin_directory = "/openbao/plugins"

plugin "kms" "transit-spire" {
  command   = "openbao-seal-spire"
  sha256sum = "__PLUGIN_SHA256__"
}

seal "transit-spire" {
  address             = "https://openbao-transit:8200"
  mount_path          = "transit"
  key_name            = "autounseal"
  trust_domain        = "example.org"
  jwt_audience        = "openbao"
  jwt_auth_role       = "kms-role"
  jwt_auth_mount_path = "jwt"
  spiffe_socket_path  = "unix:///run/spire/sockets/agent.sock"
  disable_renewal     = "false"
  # Dynamic in-memory SPIFFE Workload API mTLS:
  # Rotated X.509 SVIDs and root trust bundles are streamed in memory from SPIRE Agent.
  # No client certificate or CA files needed on disk!
}

storage "inmem" {}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

ui = true
