# ==============================================================================
# CENTRAL DE CHAVES ZATTEN — CONFIGURAÇÃO OPENBAO (COFRE / KMS SEGURO)
# Armazenamento e Rotação da Chave Mestra fora do Banco de Dados
# ==============================================================================

ui = true
disable_mlock = true

# Armazenamento seguro de arquivos persistentes
storage "file" {
  path = "/openbao/data"
}

# Listener HTTP seguro na rede interna isolada
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1 # Tráfego restrito à rede interna zatten_internal (TLS na borda)
}

api_addr = "http://openbao:8200"
cluster_addr = "http://openbao:8201"

default_lease_ttl = "168h" # 7 dias
max_lease_ttl = "720h"     # 30 dias
