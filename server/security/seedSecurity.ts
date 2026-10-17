import fs from 'node:fs';
import path from 'node:path';
import { Buffer } from 'node:buffer';
import process from 'node:process';
import { SecurityItem, SecurityFile } from './securityTypes.js';
import { computeSha256, detectContentType } from './securityStore.js';

const DB_PATH = path.join(process.cwd(), 'server', 'db.json');

function buildSecFile(secId: string, relPath: string, content: string): SecurityFile {
  const now = new Date().toISOString();
  return {
    id: `file_${secId.replace('sec_', '')}_${path.basename(relPath).replace(/[^a-zA-Z0-9]/g, '_')}`,
    securityId: secId,
    path: relPath,
    name: path.basename(relPath),
    extension: path.extname(relPath),
    contentType: detectContentType(relPath),
    sizeBytes: Buffer.byteLength(content, 'utf8'),
    sha256: computeSha256(content),
    content,
    version: '1.0.0',
    createdAt: now,
    updatedAt: now,
    deletedAt: null
  };
}

export function seedInitialSecurity(): void {
  if (!fs.existsSync(DB_PATH)) return;

  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  if (!db.security_items) db.security_items = [];
  if (!db.security_audit_logs) db.security_audit_logs = [];

  const now = new Date().toISOString();

  const INITIAL_ITEMS: Array<{
    id: string;
    slug: string;
    name: string;
    category: SecurityItem['category'];
    severity: SecurityItem['severity'];
    tags: string[];
    description: string;
    complianceStandards: string[];
    mitigatedVulnerabilities: string[];
    files: Array<{ path: string; content: string }>;
  }> = [
    // 1. HARDENING DE HEADERS HTTP
    {
      id: 'sec_hardening_headers_http',
      slug: 'hardening-headers-http',
      name: 'Hardening de Headers HTTP e Políticas de Navegador',
      category: 'hardening',
      severity: 'alto',
      tags: ['headers', 'helmet', 'csp', 'hsts', 'owasp', 'seguranca-web'],
      description: 'Configuração obrigatória de cabeçalhos de segurança HTTP (CSP, HSTS, X-Frame-Options, No-Sniff, Referrer-Policy) via Helmet para neutralizar ataques comuns no navegador.',
      complianceStandards: ['OWASP Top 10: A05 (Security Misconfiguration)', 'PCI-DSS v4.0', 'LGPD'],
      mitigatedVulnerabilities: ['Clickjacking', 'Cross-Site Scripting (XSS)', 'MIME-Type Confusion', 'Protocol Downgrade'],
      files: [
        {
          path: 'SECURITY.md',
          content: `---
name: hardening-headers-http
description: Padrão oficial de cabeçalhos HTTP com Helmet para proteção de aplicações web.
version: 1.0.0
category: hardening
severity: alto
compliance: OWASP Top 10 (A05)
---

# Hardening de Headers HTTP e Políticas de Navegador

## Objetivo
Garantir que todo tráfego web trafegue sob HTTPS estrito com cabeçalhos de segurança defensivos configurados via middleware oficial Helmet.

## Diretrizes de Implementação
1. **HSTS Obrigatório:** \`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\`
2. **Anti-Clickjacking:** \`X-Frame-Options: SAMEORIGIN\` ou \`frame-ancestors 'self'\` via Content Security Policy.
3. **No-Sniff:** \`X-Content-Type-Options: nosniff\` para impedir interpretação de arquivos como scripts executáveis.
4. **Política de Referrer:** \`Referrer-Policy: strict-origin-when-cross-origin\`.
5. **Supressão de Fingerprinting:** Remover cabeçalho \`X-Powered-By\`.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            enforce_https_only: true,
            hsts_max_age_seconds: 31536000,
            allow_inline_scripts: false,
            remove_powered_by: true,
            frame_options: "SAMEORIGIN"
          }, null, 2)
        },
        {
          path: 'checklist.md',
          content: `# Checklist de Auditoria: Headers HTTP
- [ ] O pacote \`helmet\` está instalado e ativado no topo da stack de middlewares.
- [ ] O cabeçalho \`X-Powered-By\` está ausente nas respostas.
- [ ] O HSTS está configurado com validade de pelo menos 1 ano (31536000s).
- [ ] Teste de cabeçalhos com securityheaders.com atinge nota A+.
`
        }
      ]
    },

    // 2. SANITIZAÇÃO E VALIDAÇÃO COM ZOD
    {
      id: 'sec_sanitizacao_validacao_zod',
      slug: 'sanitizacao-validacao-zod',
      name: 'Sanitização de Entrada e Validação com Zod',
      category: 'hardening',
      severity: 'critico',
      tags: ['zod', 'validacao', 'sanitizacao', 'xss', 'inputs', 'anti-injection'],
      description: 'Validação rigorosa de todos os payloads de entrada (body, query, params) com schemas estritos do Zod e rejeição de propriedades não declaradas (.strict()).',
      complianceStandards: ['OWASP Top 10: A03 (Injection)', 'OWASP Top 10: A04 (Insecure Design)'],
      mitigatedVulnerabilities: ['Mass Assignment', 'Prototype Pollution', 'XSS Injection', 'Type Confusion'],
      files: [
        {
          path: 'SECURITY.md',
          content: `---
name: sanitizacao-validacao-zod
description: Validação defensiva de entrada baseada em contrato tipado estrito com Zod.
version: 1.0.0
category: hardening
severity: critico
compliance: OWASP Top 10 (A03, A04)
---

# Sanitização de Entrada e Validação com Zod

## Regras Inegociáveis
1. **Schema Estrito (.strict()):** Nenhum campo extra desconhecido pode ser aceito em formulários ou payloads de API.
2. **Validação Antes da Execução:** O safeParse deve rodar antes de qualquer processamento de negócio ou consulta ao banco.
3. **Higienização de Strings:** Strings de texto livre devem ser aparadas (\`.trim()\`) e validadas contra limites de tamanho.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            require_strict_mode: true,
            max_string_length_default: 1000,
            prohibit_prototype_keys: ["__proto__", "constructor", "prototype"]
          }, null, 2)
        },
        {
          path: 'checklist.md',
          content: `# Checklist de Validação Zod
- [ ] Todo endpoint POST/PUT/PATCH possui schema Zod associado com \`.strict()\`.
- [ ] Erros de validação retornam status 400 sem vazar stack trace.
- [ ] Campos de identificador (UUID, slugs, IDs numéricos) usam regex específico.
`
        }
      ]
    },

    // 3. PREVENÇÃO CONTRA SQL INJECTION
    {
      id: 'sec_prevencao_sql_injection',
      slug: 'prevencao-sql-injection',
      name: 'Prevenção contra SQL Injection e Princípio do Menor Privilégio',
      category: 'banco_de_dados',
      severity: 'critico',
      tags: ['sql', 'injection', 'postgres', 'prepared-statements', 'database'],
      description: 'Bloqueio absoluto de concatenação manual de strings em queries SQL. Uso mandatório de queries parametrizadas ($1, $2) e contas com permissões restritas.',
      complianceStandards: ['OWASP Top 10: A03 (Injection)', 'ISO 27001 (A.14.2)'],
      mitigatedVulnerabilities: ['SQL Injection Cego', 'Exfiltração de Banco de Dados', 'Bypass de Autenticação'],
      files: [
        {
          path: 'SECURITY.md',
          content: `---
name: prevencao-sql-injection
description: Diretrizes de escrita de queries SQL com prepared statements e isolamento de banco.
version: 1.0.0
category: banco_de_dados
severity: critico
compliance: OWASP Top 10 (A03)
---

# Prevenção contra SQL Injection

## Práticas Obrigatórias
- **Zero Concatenação de SQL:** Nunca utilize template strings (\`\${var}\`) ou concatenação com \`+\` em consultas SQL.
- **Parâmetros Tipados:** Sempre use placeholders posicionais (\`$1, $2\` no PostgreSQL) gerenciados pelo driver do banco.
- **Usuário da Aplicação Sem Privilégios de DDL:** O usuário de conexão em produção não deve ter permissão de \`DROP TABLE\`, \`ALTER TABLE\` ou criar bancos.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist contra SQL Injection
- [ ] Todas as consultas SQL usam prepared statements ou ORM seguro.
- [ ] Nenhum parâmetro de entrada do usuário é concatenado diretamente na cláusula WHERE ou ORDER BY.
- [ ] Credenciais do banco não usam o usuário 'postgres' (superusuário) na aplicação.
`
        }
      ]
    },

    // 4. PROTEÇÃO ANTI-SSRF E WEBHOOKS
    {
      id: 'sec_protecao_anti_ssrf_webhooks',
      slug: 'protecao-anti-ssrf-webhooks',
      name: 'Proteção Anti-SSRF e Validação de Webhooks',
      category: 'rede_api',
      severity: 'critico',
      tags: ['ssrf', 'webhooks', 'hmac', 'dns', 'apis', 'anti-bypass'],
      description: 'Validação de destino e resolução DNS prévia para bloquear requisições a localhost (127.0.0.1), redes privadas (RFC 1918) e metadados de nuvem (169.254.169.254). Validação de assinatura HMAC SHA-256 em webhooks.',
      complianceStandards: ['OWASP Top 10: A10 (Server-Side Request Forgery)', 'RFC 2104'],
      mitigatedVulnerabilities: ['SSRF (Server-Side Request Forgery)', 'Acesso a Metadados AWS/GCP/Azure', 'Varredura de Rede Interna', 'Spoofing de Webhooks'],
      files: [
        {
          path: 'SECURITY.md',
          content: `---
name: protecao-anti-ssrf-webhooks
description: Bloqueio estrito de SSRF para chamadas externas e validação criptográfica de webhooks.
version: 1.0.0
category: rede_api
severity: critico
compliance: OWASP Top 10 (A10)
---

# Proteção Anti-SSRF e Validação de Webhooks

## Regras de Requisições HTTP de Saída (Outbound)
1. **Resolução DNS Antecipada:** Antes de fazer fetch, resolver o hostname e verificar se o IP resultante pertence a faixas privadas:
   - \`127.0.0.0/8\` (Loopback)
   - \`10.0.0.0/8\`, \`172.16.0.0/12\`, \`192.168.0.0/16\` (RFC 1918)
   - \`169.254.169.254\` (Link-Local / Metadados de Nuvem)
2. **Apenas Protocolos HTTP e HTTPS:** Bloquear \`file://\`, \`gopher://\`, \`ftp://\`, etc.
3. **Webhooks Assinados:** Todo webhook recebido deve verificar a assinatura HMAC SHA-256 no header com chave secreta compartilhada em tempo constante (\`timingSafeEqual\`).
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            blocked_ips: ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0"],
            blocked_cidr_ranges: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            allowed_protocols: ["https:", "http:"],
            require_hmac_sha256_webhook_verification: true
          }, null, 2)
        }
      ]
    },

    // 5. CRIPTOGRAFIA AES-256-GCM E COFRE
    {
      id: 'sec_criptografia_aes_gcm',
      slug: 'criptografia-aes-gcm',
      name: 'Criptografia de Dados Sensíveis e Cofre AES-256-GCM',
      category: 'criptografia',
      severity: 'critico',
      tags: ['criptografia', 'aes-gcm', 'vault', 'lgpd', 'segredos', 'dados-pessoais'],
      description: 'Padrão criptográfico simétrico autenticado (Authenticated Encryption with Associated Data - AEAD) utilizando AES-256-GCM com IV único de 96 bits por operação e tag de autenticação de 128 bits.',
      complianceStandards: ['NIST SP 800-38D', 'LGPD (Art. 46)', 'ISO 27001 (A.10.1)'],
      mitigatedVulnerabilities: ['Vazamento de Dados em Repouso', 'Adulteração de Ciphertext', 'Cifras Inseguras (ECB/CBC sem HMAC)'],
      files: [
        {
          path: 'SECURITY.md',
          content: `---
name: criptografia-aes-gcm
description: Criptografia autenticada AES-256-GCM para armazenamento seguro de chaves e dados sensíveis.
version: 1.0.0
category: criptografia
severity: critico
compliance: NIST SP 800-38D, LGPD
---

# Criptografia de Dados Sensíveis AES-256-GCM

## Requisitos Criptográficos
- **Algoritmo:** \`aes-256-gcm\`
- **Tamanho da Chave:** 256 bits (32 bytes binários derivados via PBKDF2 ou chave mestra de alta entropia).
- **Initialization Vector (IV):** 12 bytes (96 bits) gerados aleatoriamente com CSPRNG (\`crypto.randomBytes(12)\`) para **cada** operação de criptografia. Nunca reusar o mesmo IV.
- **Tag de Autenticação:** 16 bytes (128 bits) gerada pelo GCM e validada na decifragem antes de liberar o plaintext.
- **Formato de Armazenamento:** \`iv_hex:auth_tag_hex:ciphertext_hex\`.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            algorithm: "aes-256-gcm",
            iv_length_bytes: 12,
            auth_tag_length_bytes: 16,
            key_length_bytes: 32,
            prohibit_weak_ciphers: ["des", "3des", "rc4", "aes-ecb"]
          }, null, 2)
        }
      ]
    },

    // 6. RATE LIMITING E CONTROLE DE TAXA
    {
      id: 'sec_rate_limiting_defesa_bruteforce',
      slug: 'rate-limiting-defesa-bruteforce',
      name: 'Controle de Taxa (Rate Limit) e Defesa Brute Force',
      category: 'rede_api',
      severity: 'alto',
      tags: ['rate-limit', 'ddos', 'brute-force', 'dos', 'throttle', 'apis'],
      description: 'Políticas granulares de limitação de taxa baseadas em janela deslizante (sliding window) por IP, chave de API e tenant. Proteção especial contra ataques de força bruta em rotas de login e endpoints sensíveis.',
      complianceStandards: ['OWASP Top 10: A04 (Insecure Design)', 'OWASP API Security Top 10: API4 (Unrestricted Resource Consumption)'],
      mitigatedVulnerabilities: ['Brute Force em Senhas / MFA', 'DDoS de Aplicação', 'Esgotamento de Recursos (API Scraping)'],
      files: [
        {
          path: 'SECURITY.md',
          content: `---
name: rate_limiting_defesa_bruteforce
description: Estratégia de rate limit escalonada por sensibilidade de endpoint.
version: 1.0.0
category: rede_api
severity: alto
compliance: OWASP API4
---

# Controle de Taxa (Rate Limit) e Defesa Brute Force

## Escalonamento de Limites
1. **Rotas Críticas de Autenticação (/login, /oauth/token, /mfa):**
   - Limite: 5 requisições por janela de 15 minutos por IP/usuário.
   - Resposta: HTTP 429 Too Many Requests com cabeçalho \`Retry-After\`.
2. **Rotas Gerais de API (/api/*, /mcp/*):**
   - Limite: 100 a 300 requisições por minuto por chave/token.
3. **Cabeçalhos Padrão RFC 6585:**
   - \`RateLimit-Limit\`, \`RateLimit-Remaining\`, \`RateLimit-Reset\`.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            auth_window_minutes: 15,
            auth_max_attempts: 5,
            api_window_minutes: 1,
            api_max_requests: 120,
            standard_headers: true
          }, null, 2)
        }
      ]
    },

    // 7. AUTENTICAÇÃO MFA E OAUTH 2.1
    {
      id: 'sec_autenticacao_mfa_totp',
      slug: 'autenticacao-mfa-totp',
      name: 'Autenticação Segura MFA / TOTP e Sessões OAuth 2.1',
      category: 'autenticacao',
      severity: 'critico',
      tags: ['mfa', 'totp', 'oauth', 'pkce', 'jwt', 'autenticacao', 'tokens'],
      description: 'Implementação de autenticação em dois fatores baseada em tempo (TOTP RFC 6238) e fluxo moderno OAuth 2.1 com validação PKCE S256 obrigatória, tokens assinados assimetricamente (RS256) e rotação de refresh tokens.',
      complianceStandards: ['NIST SP 800-63B (AAL2)', 'OAuth 2.1 Draft', 'RFC 6238', 'RFC 7636'],
      mitigatedVulnerabilities: ['Roubo de Credenciais', 'Sequestro de Sessão', 'Intercepção de Código de Autorização', 'Replay Attack'],
      files: [
        {
          path: 'SECURITY.md',
          content: `---
name: autenticacao-mfa-totp
description: Padrão corporativo de autenticação multifator e sessões OAuth 2.1 protegidas com PKCE.
version: 1.0.0
category: autenticacao
severity: critico
compliance: NIST SP 800-63B, OAuth 2.1
---

# Autenticação Segura MFA / TOTP e OAuth 2.1

## Padrões de Segurança
- **TOTP (RFC 6238):** Passo de tempo de 30 segundos, algoritmo HMAC SHA-1/SHA-256 com janela de tolerância máxima de ±1 passo.
- **Armazenamento de Segredos TOTP:** O segredo base32 deve ser criptografado em repouso com o cofre AES-256-GCM.
- **OAuth 2.1 com PKCE Obrigatório:**
  - Código de autorização de uso único com expiração em 5 minutos.
  - \`code_challenge_method=S256\` obrigatório para clientes confidenciais e públicos.
  - Rotação estrita de refresh token com invalidação automática de toda a família de tokens caso um token antigo seja reutilizado.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            totp_window_step_seconds: 30,
            totp_tolerance_steps: 1,
            oauth_code_lifetime_seconds: 300,
            jwt_access_token_lifetime_seconds: 3600,
            enforce_pkce_s256: true,
            enforce_refresh_token_rotation: true
          }, null, 2)
        }
      ]
    },

    // 8. ROW LEVEL SECURITY (RLS) MULTITENANT
    {
      id: 'sec_postgres_rls_multitenant',
      slug: 'postgres-rls-multitenant',
      name: 'Row Level Security (RLS) e Isolamento Multitenant no Postgres',
      category: 'banco_de_dados',
      severity: 'critico',
      tags: ['rls', 'postgres', 'multitenant', 'isolamento', 'banco-de-dados', 'seguranca'],
      description: 'Isolamento de dados por organização no nível do motor do PostgreSQL utilizando Row Level Security (RLS). Prevenção de acesso cruzado (cross-tenant leak) mesmo em falhas da camada de aplicação.',
      complianceStandards: ['LGPD (Segregação de Dados)', 'OWASP Top 10: A01 (Broken Access Control)'],
      mitigatedVulnerabilities: ['Vazamento de Dados Multitenant', 'Acesso Horizontal Não Autorizado', 'Injeção de Tenant ID'],
      files: [
        {
          path: 'SECURITY.md',
          content: `---
name: postgres-rls-multitenant
description: Isolamento absoluto de dados multitenant usando Row Level Security no PostgreSQL.
version: 1.0.0
category: banco_de_dados
severity: critico
compliance: OWASP A01, LGPD
---

# Row Level Security (RLS) no PostgreSQL

## Arquitetura de Isolamento
1. **Ativação de RLS na Tabela:**
   \`\`\`sql
   ALTER TABLE leads ENABLE ROW LEVEL SECURITY;
   ALTER TABLE leads FORCE ROW LEVEL SECURITY;
   \`\`\`
2. **Definição de Política por Tenant Context:**
   \`\`\`sql
   CREATE POLICY tenant_isolation_policy ON leads
     FOR ALL
     USING (organization_id = NULLIF(current_setting('app.current_org_id', true), ''))
     WITH CHECK (organization_id = NULLIF(current_setting('app.current_org_id', true), ''));
   \`\`\`
3. **Injeção de Contexto no Pool de Conexões:**
   - Antes de cada query, a aplicação executa: \`SET LOCAL app.current_org_id = 'org_xyz';\`.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            enforce_force_rls: true,
            tenant_setting_key: "app.current_org_id",
            require_tenant_id_in_all_primary_tables: true
          }, null, 2)
        }
      ]
    }
  ];

  for (const itemData of INITIAL_ITEMS) {
    let existing = db.security_items.find((s: any) => s.id === itemData.id || s.slug === itemData.slug);
    const builtFiles = itemData.files.map(f => buildSecFile(itemData.id, f.path, f.content));

    if (!existing) {
      existing = {
        id: itemData.id,
        name: itemData.name,
        slug: itemData.slug,
        description: itemData.description,
        category: itemData.category,
        severity: itemData.severity,
        tags: itemData.tags,
        status: 'ativo',
        complianceStandards: itemData.complianceStandards,
        mitigatedVulnerabilities: itemData.mitigatedVulnerabilities,
        files: builtFiles,
        createdAt: now,
        updatedAt: now
      };
      db.security_items.push(existing);
    } else {
      // Atualiza metadados e arquivos preservando histórico
      existing.name = itemData.name;
      existing.slug = itemData.slug;
      existing.description = itemData.description;
      existing.category = itemData.category;
      existing.severity = itemData.severity;
      existing.tags = Array.from(new Set([...(existing.tags || []), ...itemData.tags]));
      existing.complianceStandards = itemData.complianceStandards;
      existing.mitigatedVulnerabilities = itemData.mitigatedVulnerabilities;
      existing.files = builtFiles;
      existing.updatedAt = now;
    }
  }

  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
  console.log(`✅ Biblioteca de Segurança inicializada com sucesso: ${INITIAL_ITEMS.length} tecnologias e métodos cadastrados no db.json.`);
}
