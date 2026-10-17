/**
 * TIPOS, SCHEMAS ZOD E CONSTANTES OAUTH 2.1 & OPENID CONNECT
 * Central Privada de Conexões Zatten — Firstsys
 * Conforme RFC 6749, RFC 7636 (PKCE), RFC 8414, RFC 7009 e Especificações MCP / ChatGPT
 */

import { z } from 'zod';

// ==============================================================================
// 1. ESCOPOS MÍNIMOS OAUTH 2.1 (Princípio do Menor Privilégio & Ferramentas MCP)
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
  'audit:read',

  // 24 Ferramentas / Funções Zatten (Escopos Granulares por Função)
  'firstsys_get_profile',
  'zatten_list_connections',
  'zatten_get_connection_status',
  'zatten_get_leads',
  'zatten_kanban_get',
  'zatten_tags_get',
  'zatten_leads_leadnumber_get',
  'zatten_leads_leadnumber_notes_patch',
  'zatten_leads_leadnumber_properties_patch',
  'zatten_leads_leadnumber_threads_get',
  'zatten_leads_leadnumber_thread_patch',
  'zatten_leads_leadnumber_kanban_patch',
  'zatten_leads_leadnumber_assignee_patch',
  'zatten_leads_leadnumber_toggle_attendant_response_post',
  'zatten_leads_leadnumber_tag_post',
  'zatten_leads_leadnumber_tag_delete',
  'zatten_messages_text_post',
  'zatten_send_message',
  'zatten_messages_template_post',
  'zatten_messages_audio_post',
  'zatten_messages_image_post',
  'zatten_messages_file_post',
  'zatten_messages_video_post',
  'zatten_messages_history_get',
  'zatten_attendants_list',
  'zatten_templates_list',
  'zatten_users_get',
  'zatten_templates_get',
  'zatten_explain_lead_lookup',

  // Ferramentas com prefixo tool:
  'tool:firstsys_get_profile',
  'tool:zatten_list_connections',
  'tool:zatten_get_connection_status',
  'tool:zatten_get_leads',
  'tool:zatten_kanban_get',
  'tool:zatten_tags_get',
  'tool:zatten_leads_leadnumber_get',
  'tool:zatten_leads_leadnumber_notes_patch',
  'tool:zatten_leads_leadnumber_properties_patch',
  'tool:zatten_leads_leadnumber_threads_get',
  'tool:zatten_leads_leadnumber_thread_patch',
  'tool:zatten_leads_leadnumber_kanban_patch',
  'tool:zatten_leads_leadnumber_assignee_patch',
  'tool:zatten_leads_leadnumber_toggle_attendant_response_post',
  'tool:zatten_leads_leadnumber_tag_post',
  'tool:zatten_leads_leadnumber_tag_delete',
  'tool:zatten_messages_text_post',
  'tool:zatten_send_message',
  'tool:zatten_messages_template_post',
  'tool:zatten_messages_audio_post',
  'tool:zatten_messages_image_post',
  'tool:zatten_messages_file_post',
  'tool:zatten_messages_video_post',
  'tool:zatten_messages_history_get',
  'tool:zatten_attendants_list',
  'tool:zatten_templates_list',
  'tool:zatten_users_get',
  'tool:zatten_templates_get',
  'tool:zatten_explain_lead_lookup',

  // Escopos de Skills e Capacidades Firstsys
  'skills:read',
  'skills:write',
  'skills:manage',
  'firstsys_skills_list',
  'firstsys_skills_get',
  'firstsys_skills_create',
  'firstsys_skills_update',
  'firstsys_skills_delete',
  'firstsys_skills_install',
  'firstsys_skills_uninstall',
  'firstsys_skills_installations_list',
  'firstsys_skills_installations_create',
  'firstsys_skills_installations_delete',
  'firstsys_skill_files_list',
  'firstsys_skill_files_get',
  'firstsys_skill_files_save',
  'firstsys_skill_files_create',
  'firstsys_skill_files_update',
  'firstsys_skill_files_delete',
  'firstsys_skill_files_restore',
  'firstsys_skills_import_preview',
  'firstsys_skills_import_inspect',
  'firstsys_skills_import_from_git',
  'firstsys_skills_import_commit',
  'firstsys_skills_import_status',
  'firstsys_skills_sync_preview',
  'firstsys_skills_sync_inspect',
  'firstsys_skills_sync_from_git',
  'firstsys_skills_sync_commit',
  'firstsys_skills_versions_list',
  'firstsys_skills_versions_get',
  'firstsys_skills_versions_create',
  'firstsys_skills_versions_compare',
  'firstsys_skills_versions_diff',
  'firstsys_skills_versions_restore',
  'firstsys_skills_versions_rollback',
  'firstsys_skills_audit_list',
  'firstsys_skills_dependencies_list',
  'firstsys_skills_permissions_get',
  'firstsys_skills_permissions_update',

  // Prefixo tool: para todas as ferramentas de skills
  'tool:firstsys_skills_list',
  'tool:firstsys_skills_get',
  'tool:firstsys_skills_create',
  'tool:firstsys_skills_update',
  'tool:firstsys_skills_delete',
  'tool:firstsys_skills_install',
  'tool:firstsys_skills_uninstall',
  'tool:firstsys_skills_installations_list',
  'tool:firstsys_skills_installations_create',
  'tool:firstsys_skills_installations_delete',
  'tool:firstsys_skill_files_list',
  'tool:firstsys_skill_files_get',
  'tool:firstsys_skill_files_save',
  'tool:firstsys_skill_files_create',
  'tool:firstsys_skill_files_update',
  'tool:firstsys_skill_files_delete',
  'tool:firstsys_skill_files_restore',
  'tool:firstsys_skills_import_preview',
  'tool:firstsys_skills_import_inspect',
  'tool:firstsys_skills_import_from_git',
  'tool:firstsys_skills_import_commit',
  'tool:firstsys_skills_import_status',
  'tool:firstsys_skills_sync_preview',
  'tool:firstsys_skills_sync_inspect',
  'tool:firstsys_skills_sync_from_git',
  'tool:firstsys_skills_sync_commit',
  'tool:firstsys_skills_versions_list',
  'tool:firstsys_skills_versions_get',
  'tool:firstsys_skills_versions_create',
  'tool:firstsys_skills_versions_compare',
  'tool:firstsys_skills_versions_diff',
  'tool:firstsys_skills_versions_restore',
  'tool:firstsys_skills_versions_rollback',
  'tool:firstsys_skills_audit_list',
  'tool:firstsys_skills_dependencies_list',
  'tool:firstsys_skills_permissions_get',
  'tool:firstsys_skills_permissions_update',

  // Escopos de Segurança Corporativa Firstsys
  'security:read',
  'security:write',
  'security:manage',
  'firstsys_security_list',
  'firstsys_security_get',
  'firstsys_security_create',
  'firstsys_security_update',
  'firstsys_security_delete',
  'firstsys_security_tag_add',
  'firstsys_security_tag_remove',
  'firstsys_security_files_list',
  'firstsys_security_files_get',
  'firstsys_security_files_save',
  'firstsys_security_files_delete',
  'firstsys_security_files_restore',
  'firstsys_security_audit_list',

  // Prefixo tool: para ferramentas de segurança
  'tool:firstsys_security_list',
  'tool:firstsys_security_get',
  'tool:firstsys_security_create',
  'tool:firstsys_security_update',
  'tool:firstsys_security_delete',
  'tool:firstsys_security_tag_add',
  'tool:firstsys_security_tag_remove',
  'tool:firstsys_security_files_list',
  'tool:firstsys_security_files_get',
  'tool:firstsys_security_files_save',
  'tool:firstsys_security_files_delete',
  'tool:firstsys_security_files_restore',
  'tool:firstsys_security_audit_list'
] as const;

export type OAuthScope = typeof OAUTH_SCOPES[number] | string;

export const OAuthScopeSchema = z.string();

export const ScopesStringSchema = z.string().transform((val) => {
  const parts = val.trim().split(/\s+/).filter(Boolean);
  return parts;
}).pipe(z.array(z.string()));

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
  nbf?: number;                // Not Before
  iat: number;                 // Issued At
  jti?: string;                // ID único do token para prevenção de replay
  org_id?: string;             // Organização associada (ex: org_firstsys_prod)
  role?: UserRole;             // Papel do usuário
  scope?: string;              // Escopos concedidos separados por espaço
  client_id?: string;          // ID do cliente que solicitou o token
  token_family_id?: string;    // ID de rastreamento de rotação de refresh token
  email?: string;              // Claim de e-mail OIDC (RFC / OIDC Core 1.0)
  email_verified?: boolean;    // Claim de verificação OIDC
  nonce?: string;              // Claim de nonce OIDC
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
