storage "inmem" {}

listener "tcp" {
  address                            = "0.0.0.0:8200"
  tls_cert_file                      = "/openbao/tls/transit-server.crt"
  tls_key_file                       = "/openbao/tls/transit-server.key"
  tls_client_ca_file                 = "/openbao/tls/ca.crt"
  tls_require_and_verify_client_cert = "true"
}

ui = true
