/**
 * TIPOS, SCHEMAS ZOD E CONSTANTES OAUTH 2.1 & OPENID CONNECT
 * Central Privada de Conexões Zatten — Firstsys
 * Conforme RFC 6749, RFC 7636 (PKCE), RFC 8414, RFC 7009 e Especificações MCP / ChatGPT
 */

import { z } from 'zod';

// ==============================================================================
// 1. ESCOPOS MÍNIMOS OAUTH 2.1 (Princípio do Menor Privilégio)
// ==============================================================================
export const OAUTH_SCOPES = [
  'openid',
  'profile',
  'email',
  'connections:read',
  'connections:manage',
  'zatten:read',
  'zatten:write',
  'zatten:messages',
  'audit:read'
] as const;

export type OAuthScope = typeof OAUTH_SCOPES[number];

export const OAuthScopeSchema = z.enum(OAUTH_SCOPES);

export const ScopesStringSchema = z.string().transform((val) => {
  const parts = val.trim().split(/\s+/).filter(Boolean);
  return parts;
}).pipe(z.array(OAuthScopeSchema));

// ==============================================================================
// 2. PAPÉIS DE USUÁRIO E ENTIDADES DE SEGURANÇA
// ==============================================================================
export const USER_ROLES = ['owner', 'admin', 'operator', 'viewer'] as const;
export type UserRole = typeof USER_ROLES[number];
export const UserRoleSchema = z.enum(USER_ROLES);

export const CONNECTION_STATUSES = ['active', 'invalid', 'paused', 'revoked'] as const;
export type ConnectionStatus = typeof CONNECTION_STATUSES[number];
export const ConnectionStatusSchema = z.enum(CONNECTION_STATUSES);

// ==============================================================================
// 3. SCHEMAS DE REQUISIÇÃO OAUTH 2.1
// ==============================================================================

/**
 * Parâmetros de Solicitação de Autorização (/oauth/authorize)
 * Exige response_type=code, code_challenge e code_challenge_method=S256 obrigatório
 */
export const AuthorizationRequestSchema = z.object({
  response_type: z.literal('code', {
    error: 'OAuth 2.1 proíbe implicit grant; apenas response_type=code é aceito.'
  }),
  client_id: z.string().min(1, 'client_id é obrigatório'),
  redirect_uri: z.string().url('redirect_uri deve ser uma URL válida'),
  scope: ScopesStringSchema,
  state: z.string().min(4, 'state é obrigatório e deve ter alta entropia para prevenir CSRF'),
  code_challenge: z.string().min(43).max(128, 'code_challenge PKCE inválido').optional(),
  code_challenge_method: z.literal('S256', {
    error: 'OAuth 2.1 exige code_challenge_method=S256; plain foi descontinuado.'
  }).optional(),
  nonce: z.string().optional(),
  resource: z.string().url('resource deve ser um identificador canônico de URI válido').optional(),
});

export type AuthorizationRequest = z.infer<typeof AuthorizationRequestSchema>;

/**
 * Parâmetros para Troca de Token (/oauth/token)
 * Suporta exclusivamente authorization_code e refresh_token
 */
export const TokenExchangeCodeSchema = z.object({
  grant_type: z.literal('authorization_code'),
  client_id: z.string().min(1).optional(),
  client_secret: z.string().optional(), // Clientes confidenciais ou ChatGPT Actions enviam client_secret
  code: z.string().min(16, 'Código de autorização inválido'),
  redirect_uri: z.string().url().optional(),
  code_verifier: z.string().min(43).max(128, 'code_verifier deve ter entre 43 e 128 caracteres').optional(),
  resource: z.string().url().optional(),
});

export const TokenRefreshSchema = z.object({
  grant_type: z.literal('refresh_token'),
  client_id: z.string().min(1).optional(),
  client_secret: z.string().optional(),
  refresh_token: z.string().min(32, 'refresh_token inválido'),
  scope: ScopesStringSchema.optional(),
  resource: z.string().url().optional(),
});

export const TokenRequestSchema = z.discriminatedUnion('grant_type', [
  TokenExchangeCodeSchema,
  TokenRefreshSchema,
]);

export type TokenRequest = z.infer<typeof TokenRequestSchema>;

/**
 * Parâmetros de Revogação de Token (/oauth/revoke - RFC 7009)
 */
export const RevocationRequestSchema = z.object({
  token: z.string().min(1, 'token a ser revogado é obrigatório'),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
});

export type RevocationRequest = z.infer<typeof RevocationRequestSchema>;

// ==============================================================================
// 4. PAYLOAD DO TOKEN JWT E CLAIMS OAUTH / OIDC
// ==============================================================================
export interface OAuthJwtPayload {
  iss: string;                 // Emissor canônico (ex: https://auth.firstsys.com.br)
  sub: string;                 // ID opaco permanente do usuário (ex: usr_01j7...)
  aud: string | string[];      // Recurso MCP autorizado (ex: https://mcp.firstsys.com.br/mcp)
  exp: number;                 // Expiração curta (UNIX timestamp em segundos)
  nbf: number;                 // Not Before
  iat: number;                 // Issued At
  jti: string;                 // ID único do token para prevenção de replay
  org_id: string;              // Organização associada (ex: org_firstsys_prod)
  role: UserRole;              // Papel do usuário
  scope: string;               // Escopos concedidos separados por espaço
  client_id: string;           // ID do cliente que solicitou o token
  token_family_id?: string;    // ID de rastreamento de rotação de refresh token
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
  id_token?: string;
}

// ==============================================================================
// 5. METADADOS DE RECURSO PROTEGIDO MCP & CHATGPT (RFC Protected Resource Draft)
// ==============================================================================
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported: OAuthScope[];
  bearer_methods_supported: ['header'];
  resource_documentation: string;
}
