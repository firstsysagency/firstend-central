#!/bin/sh
# ==============================================================================
# SCRIPT DE INICIALIZAÇÃO AUTOMATIZADA DO OPENBAO (COFRE KMS)
# Central de Chaves Zatten — Proteção Militar da Chave Mestra fora do Banco
# ==============================================================================

set -e

export BAO_ADDR="http://127.0.0.1:8200"

echo "[OPENBAO-INIT] Aguardando serviço OpenBao iniciar..."
until wget -q --spider "$BAO_ADDR/v1/sys/health" || [ $? -eq 2 ]; do
  sleep 1
done

echo "[OPENBAO-INIT] Verificando status de inicialização..."
INIT_STATUS=$(wget -qO- "$BAO_ADDR/v1/sys/init" | grep -o '"initialized":true' || true)

if [ -z "$INIT_STATUS" ]; then
  echo "[OPENBAO-INIT] Inicializando novo cofre com 1 share para dev/staging..."
  INIT_RESPONSE=$(wget -qO- --post-data='{"secret_shares": 1, "secret_threshold": 1}' "$BAO_ADDR/v1/sys/init")
  
  UNSEAL_KEY=$(echo "$INIT_RESPONSE" | grep -o '"keys":\["[^"]*"' | cut -d'"' -f4)
  ROOT_TOKEN=$(echo "$INIT_RESPONSE" | grep -o '"root_token":"[^"]*"' | cut -d'"' -f4)

  echo "[OPENBAO-INIT] Cofre inicializado com sucesso."
  echo "ATENCAO: Guarde esta Unseal Key e Root Token em local seguro fora do servidor!"
  echo "UNSEAL_KEY=$UNSEAL_KEY"
  echo "ROOT_TOKEN=$ROOT_TOKEN"

  # Desbloqueio (Unseal)
  wget -qO- --post-data="{\"key\": \"$UNSEAL_KEY\"}" "$BAO_ADDR/v1/sys/unseal" > /dev/null
  echo "[OPENBAO-INIT] Cofre desbloqueado (Unsealed)."

  export BAO_TOKEN="$ROOT_TOKEN"

  # Habilitar Transit Secrets Engine (KMS de Chave Mestra)
  echo "[OPENBAO-INIT] Habilitando Transit Secrets Engine..."
  wget -qO- --header="X-Vault-Token: $BAO_TOKEN" \
       --post-data='{"type": "transit", "description": "KMS de Cifra de Chaves Zatten"}' \
       "$BAO_ADDR/v1/sys/mounts/transit" || true

  # Criar a Chave Mestra com AES-256-GCM
  echo "[OPENBAO-INIT] Criando chave mestra zatten-master-key (AES-256-GCM)..."
  wget -qO- --header="X-Vault-Token: $BAO_TOKEN" \
       --post-data='{"type": "aes256-gcm96", "exportable": false, "allow_plaintext_backup": false}' \
       "$BAO_ADDR/v1/transit/keys/zatten-master-key" || true

  # Configurar política de menor privilégio para a API Zatten
  echo "[OPENBAO-INIT] Criando política zatten-app-policy..."
  POLICY_RULES='path "transit/encrypt/zatten-master-key" { capabilities = ["update"] }\npath "transit/decrypt/zatten-master-key" { capabilities = ["update"] }\npath "transit/keys/zatten-master-key/rotate" { capabilities = ["update"] }\npath "transit/keys/zatten-master-key" { capabilities = ["read"] }'
  
  wget -qO- --header="X-Vault-Token: $BAO_TOKEN" \
       --post-data="{\"policy\": \"$POLICY_RULES\"}" \
       "$BAO_ADDR/v1/sys/policies/acl/zatten-app-policy" || true

  echo "[OPENBAO-INIT] Chave mestra configurada com sucesso fora do banco de dados!"
else
  echo "[OPENBAO-INIT] OpenBao já se encontra inicializado."
fi
