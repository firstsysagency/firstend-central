# Central Privada de Conexões Zatten — Firstsys (Deploy & Arquitetura)

Este repositório contém a infraestrutura e o código da Central Privada de Conexões Zatten da Firstsys, incluindo:
- **Provedor OAuth 2.1 / OIDC:** Authorization Code Flow com PKCE S256 obrigatório, tokens assimétricos RS256, rotação de refresh tokens e detecção de reuso.
- **Servidor MCP Remoto:** Endpoint JSON-RPC 2.0 (`/mcp`) para ChatGPT com suporte a OAuth Protected Resource Metadata, validação de audiência (`aud`) e confirmação humana de 2 etapas para escrita.
- **Cofre de Segredos:** Armazenamento seguro de chaves Zatten (`x-api-key`) em OpenBao / AES-256-GCM com zero vazamento para clientes ou logs.
- **Proxy Reverso Nginx:** TLS 1.3, Let's Encrypt automático, headers de segurança (HSTS, CSP) e rate limiting de borda.

---

## 1. Topologia da Arquitetura

```text
[ ChatGPT (OpenAI) ]                  [ Navegador / Painel Firstsys ]
          |                                          |
          | HTTPS (443)                              | HTTPS (443)
          v                                          v
+--------------------------------------------------------------------------+
|                     NGINX (Borda Pública: Portas 80 / 443)               |
|      auth.seudominio.com  |  mcp.seudominio.com  |  keys.seudominio.com  |
+--------------------------------------------------------------------------+
                                  |
               REDE INTERNA DOCKER (zatten_internal)
               [Sem portas de banco ou cofre expostas na VPS]
                                  |
                                  v
+--------------------------------------------------------------------------+
|                     APLICAÇÃO TYPESCRIPT (Node.js)                       |
|   - OAuth 2.1 Server (PKCE S256, RS256, JWKS, Token Family Rotation)    |
|   - Servidor MCP Remoto (Protected Resource, aud=mcp, 2-Step Confirm)    |
|   - ZattenClient (Fila serial de 1 req/s por conexão, Redaction de Logs) |
+--------------------------------------------------------------------------+
        |                         |                         |
        v                         v                         v
+---------------+         +---------------+         +---------------+
|  PostgreSQL   |         |    OpenBao    |         |    Valkey     |
| (RLS & Audit) |         | (Chave Mestra)|         | (Rate Limit & |
|               |         |               |         |  Fila MCP)    |
+---------------+         +---------------+         +---------------+
```

---

## 2. Requisitos da VPS

- **Sistema Operacional:** Ubuntu 22.04 LTS / 24.04 LTS ou Debian 12
- **Hardware Mínimo:** 2 vCPUs, 2 GB RAM, 20 GB SSD
- **Portas Abertas no Firewall (UFW):**
  - `80/tcp` (HTTP para validação Let's Encrypt e redirecionamento 301)
  - `443/tcp` (HTTPS tráfego seguro)
  - `22/tcp` (SSH restrito a chave pública)
- **Softwares:** Docker Engine 25+ e Docker Compose v2+

---

## 3. Passo a Passo de Instalação e Deploy

### Passo 1: Clonar o Repositório na VPS
```bash
git clone https://github.com/firstsys/zatten-central.git /opt/zatten-central
cd /opt/zatten-central/deploy
```

### Passo 2: Configurar o Arquivo `.env`
Copie o template e preencha as variáveis seguras:
```bash
cp .env.example .env
```

Gere uma chave mestra de 32 bytes (64 caracteres hexadecimais):
```bash
openssl rand -hex 32
```
Cole o valor gerado na variável `APP_ENCRYPTION_KEY_HEX` no `.env`.
Configure também as senhas do PostgreSQL e do Valkey.

### Passo 3: Apontamentos de DNS
Crie os registros DNS do tipo **A** apontando para o IP público da VPS:
- `auth.seudominio.com` -> IP da VPS
- `mcp.seudominio.com` -> IP da VPS
- `keys.seudominio.com` -> IP da VPS

### Passo 4: Inicialização dos Certificados SSL (Let's Encrypt)
Na primeira execução, inicialize os certificados usando o Certbot:
```bash
docker compose run --rm certbot certonly --webroot --webroot-path=/var/www/certbot \
  -d auth.seudominio.com \
  -d mcp.seudominio.com \
  -d keys.seudominio.com \
  --email admin@seudominio.com \
  --agree-tos --no-eff-email
```

### Passo 5: Inicializar o Banco de Dados com RLS
Execute o script DDL com as tabelas, índices e políticas de Row Level Security:
```bash
docker compose up -d db
docker compose exec -T db psql -U zatten_admin -d zatten_central_prod < server/db/schema.sql
```

### Passo 6: Subir Toda a Stack
```bash
docker compose up -d --build
```

Verifique a saúde de todos os contêineres:
```bash
docker compose ps
```

---

## 4. Testes e Validação de Segurança

Para executar a suíte automatizada de testes de segurança (22 testes cobrindo PKCE S256, Redirect URI estrita, RS256, audiência MCP, rotação/reuso de refresh token, AES-256-GCM, redaction de logs e fila de 1 req/s):

```bash
npx tsx tests/oauth_security.test.ts
```

---

## 5. Integração com o ChatGPT / OpenAI

1. No ChatGPT ou na configuração do Custom GPT / Ação MCP:
   - **URL do Servidor MCP:** `https://mcp.seudominio.com/mcp`
   - O ChatGPT fará uma chamada GET em `https://mcp.seudominio.com/.well-known/oauth-protected-resource` e obterá automaticamente o endpoint de autorização.
2. O usuário é redirecionado para a página segura de login da Firstsys (`https://auth.seudominio.com/oauth/authorize`).
3. Administradores realizam verificação MFA/TOTP obrigatória.
4. O ChatGPT recebe o Access Token RS256 com audiência restrita a `https://mcp.seudominio.com/mcp`.
5. Todas as operações de leitura e escrita operam exclusivamente com o `connectionId` opaco.

---

## 6. Checklist de Segurança

Consulte o arquivo [`SECURITY_CHECKLIST.md`](file:///c:/Firstsys/Zatten/Central/deploy/SECURITY_CHECKLIST.md) para detalhes completos de auditoria e conformidade.
