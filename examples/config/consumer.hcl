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
  tls_ca_cert         = "/openbao/tls/ca.crt"
  tls_client_cert     = "/openbao/tls/consumer-client.crt"
  tls_client_key      = "/openbao/tls/consumer-client.key"
  tls_server_name     = "openbao-transit"
}

storage "inmem" {}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

ui = true
