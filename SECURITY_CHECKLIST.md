# Checklist e Auditoria de Segurança — Central Zatten & OAuth 2.1 / MCP Firstsys

Este documento detalha o checklist de conformidade com todas as regras de segurança estabelecidas para a Central Privada de Conexões Zatten da Firstsys, o fluxo OAuth 2.1 e o servidor MCP remoto integrado ao ChatGPT.

---

## 1. Fronteiras de Segurança e Proteção das Chaves Zatten

- [x] **Zero Exposição da Chave no Cliente/ChatGPT:**
  - A `x-api-key` da Zatten nunca é trafegada para o ChatGPT, navegador, token OAuth, parâmetros de URL ou query string.
  - O navegador envia a chave apenas uma vez via HTTPS no momento do cadastro.
  - A chave é cifrada no ato da recepção e nunca mais é devolvida em nenhuma resposta HTTP (`GET /api/connections` retorna apenas metadados seguros: `id`, `name`, `status`, `lastUsedAt`, etc.).
- [x] **Identificador Opaco para o MCP:**
  - O servidor MCP opera exclusivamente com `connectionId` opaco (ex: `conn_...`).
  - O MCP consulta a autorização do usuário na organização e recupera a chave internamente via memória volátil no backend apenas durante o disparo da chamada.
- [x] **Cofre de Segredos (OpenBao & AES-256-GCM):**
  - Integração implementada em `SecretsVault` com chave mestra via OpenBao Transit Engine ou AES-256-GCM autenticado (com IV de 96 bits único por cifragem e tag de autenticação de 128 bits).
  - Versionamento da chave de cifragem (`v1:...`) suportando rotação sem indisponibilidade.
- [x] **Redaction Centralizada de Logs:**
  - O logger estruturado mascara automaticamente campos como `x-api-key`, `Authorization`, `token`, `secret`, `password`, `code_verifier` e cookies, prevenindo vazamentos em logs de auditoria e depuração.

---

## 2. OAuth 2.1 e OpenID Connect (OIDC)

- [x] **Authorization Code Flow com PKCE S256 Obrigatório:**
  - Implementado em `oauthRoutes.ts` e `oauthStore.ts`.
  - Rejeição estrita de chamadas sem `code_challenge` ou com `code_challenge_method != 'S256'`.
  - Validação estrita do `code_verifier` (comprimento entre 43 e 128 caracteres, hash SHA-256 base64url).
- [x] **Eliminação de Modos Obsoletos e Inseguros:**
  - *Implicit Grant* desabilitado.
  - *Resource Owner Password Credentials* desabilitado.
  - Tokens em query string terminantemente proibidos.
- [x] **Validação Exata de Redirect URIs:**
  - Comparação estrita caractere por caractere contra as URIs pré-cadastradas no `oauthStore`.
  - Proibição absoluta de curingas (`*`), caminhos relativos ou correspondências parciais.
- [x] **Ciclo de Vida de Tokens e Assinatura Criptográfica:**
  - Access Tokens com tempo de vida curto (15 minutos), emitidos como JWT assinados assimetricamente com **RS256** (RSA 2048-bit).
  - JWKS público exposto em `/.well-known/jwks.json` com suporte a chave rotativa (`kid`).
  - Refresh Tokens com rotação contínua (cada uso invalida o refresh token anterior e gera um novo par).
  - **Detecção de Reutilização de Família (Token Family Reuse Detection):** Ao detectar o uso de um refresh token já consumido, toda a família de tokens do usuário é revogada imediatamente para conter suspeita de sequestro de sessão.
- [x] **MFA / 2FA Obrigatório:**
  - Usuários com papéis administrativos (`owner` e `admin`) exigem segundo fator (TOTP) verificado antes da concessão do código de autorização OAuth.
- [x] **Escopos Mínimos Implementados:**
  - `openid` e `profile`: identificação básica e perfil permanente.
  - `connections:read`: listar conexões e metadados.
  - `connections:manage`: cadastrar, rotacionar ou revogar conexões Zatten.
  - `zatten:read`: consulta de leads, status e pipelines Zatten.
  - `zatten:write`: criação/atualização de leads e dados no CRM.
  - `zatten:messages`: envio de mensagens ativas e notificações.
  - `audit:read`: inspeção de logs de eventos e rastreabilidade.

---

## 3. Servidor MCP Remoto e ChatGPT

- [x] **Descoberta de Recursos Protegidos (RFC 9207 / OAuth Protected Resource Metadata):**
  - Endpoint `GET /.well-known/oauth-protected-resource` implementado em `mcpRouter.ts`, declarando o identificador canônico do recurso (`https://mcp.seudominio.com/mcp`), os servidores de autorização compatíveis (`https://auth.seudominio.com`) e os escopos exigidos.
- [x] **Validação da Audiência (`aud`):**
  - O parâmetro `resource` é validado durante a emissão do token e fixado como audiência (`aud`).
  - O middleware do MCP valida estritamente se `token.aud === MCP_RESOURCE_IDENTIFIER`, rejeitando tokens emitidos para outros serviços.
- [x] **Desafio de Autenticação Padronizado:**
  - Requisições sem token ou com token inválido recebem `401 Unauthorized` com o cabeçalho `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`.
- [x] **Ferramentas Privadas com Esquemas de Segurança Declarados:**
  - Nenhuma ferramenta MCP de acesso a dados Zatten opera anonimamente.
  - Todas as ferramentas declaram `securitySchemes` com OAuth 2.1 e escopos específicos.
- [x] **Ferramenta de Perfil Seguro:**
  - Implementada `firstsys_get_profile`, retornando identificadores opacos, organização e papéis, sem expor chaves ou credenciais.
- [x] **Confirmação Explícita de 2 Etapas para Escrita:**
  - Ferramentas de impacto (`firstsys_send_message`, `firstsys_create_lead`, etc.) exigem um parâmetro obrigatório de confirmação (`confirmationToken`) gerado em fase prévia de inspeção, impedindo execuções automáticas acidentais pelo modelo de IA.

---

## 4. Comunicação com a API Zatten e Resiliência

- [x] **Controle de Taxa por Chave (Rate Limiting):**
  - Fila serial por conexão implementada em `ZattenClient`, garantindo o limite de 1 requisição por segundo por chave de projeto.
- [x] **Timeouts Estritos:**
  - Limite de 10.000 ms em todas as chamadas HTTP à API Zatten, impedindo esgotamento de conexões.
- [x] **Tratamento Seguro de Códigos de Erro:**
  - Erros `400 Bad Request`, `401 Unauthorized` e `429 Too Many Requests` tratados sem repetição cega e sem ecoar cabeçalhos de autenticação nos logs ou na resposta ao ChatGPT.
  - Em caso de `401`, o status da conexão é atualizado automaticamente para `invalid` no banco de dados.

---

## 5. Arquitetura de Containers, VPS e Nginx

- [x] **Exposição Pública Estrita (Apenas 80 e 443):**
  - Somente o serviço Nginx expõe portas para a internet do host.
  - PostgreSQL, OpenBao, Valkey e a aplicação Node.js rodam em redes internas privadas (`zatten_internal`), sem mapeamento de portas externas.
- [x] **Nginx de Borda Hardened:**
  - TLS 1.3 / TLS 1.2 com cifras fortes.
  - Redirecionamento 301 forçado de HTTP para HTTPS.
  - Cabeçalhos de proteção: `Strict-Transport-Security` (HSTS), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` e `Content-Security-Policy`.
  - Rate limiting por IP na borda (`limit_req_zone` de 10 req/s com burst controlado).
- [x] **Isolamento de Contêineres:**
  - Nenhum container roda com privilégios de root desnecessários ou mapeamento do socket do Docker (`/var/run/docker.sock`).
  - Imagens com tags fixas (`postgres:16-alpine`, `nginx:1.27-alpine`, `valkey/valkey:8.0-alpine`).

---

## 6. Trilha de Auditoria e Privacidade

- [x] **Eventos de Auditoria Imutáveis:**
  - Tabela `audit_logs` no PostgreSQL com gatilho que impede `UPDATE` ou `DELETE`.
  - Registro de todas as operações críticas: login, emissão/revogação de tokens, criação, teste, pausa, ativação e rotação de conexões, e chamadas de ferramentas MCP.
- [x] **Proteção de Dados Pessoais (LGPD):**
  - Nenhum dado pessoal de leads ou payloads completos de mensagens é persistido nos logs do servidor.
