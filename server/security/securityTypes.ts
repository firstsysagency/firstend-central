import { z } from 'zod';

// ==============================================================================
// 1. CONSTANTES E POLÍTICAS DE ARQUIVOS DE SEGURANÇA
// ==============================================================================

export const ALLOWED_SECURITY_EXTENSIONS = [
  '.md', '.txt', '.json', '.yaml', '.yml', '.toml',
  '.ts', '.tsx', '.js', '.mjs', '.cjs', '.py',
  '.sh', '.ps1', '.html', '.css', '.sql'
] as const;

export const BLOCKED_SECURITY_EXTENSIONS = [
  '.env', '.key', '.pem', '.pfx', '.p12', '.crt', '.cer',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.iso', '.zip',
  '.tar', '.gz', '.7z', '.rar', '.sqlite', '.db'
] as const;

export const SENSITIVE_SECURITY_FILENAMES = [
  '.env', '.env.local', '.env.production', '.env.development',
  'id_rsa', 'id_ed25519', 'credentials.json', 'service-account.json',
  'secret', 'secrets.json', 'htpasswd', 'shadow'
] as const;

export const MAX_SECURITY_FILE_SIZE_BYTES = 1024 * 1024; // 1 MB por arquivo de texto
export const MAX_TOTAL_SECURITY_SIZE_BYTES = 15 * 1024 * 1024; // 15 MB por item completo

// ==============================================================================
// 2. CATEGORIAS E NÍVEIS DE SEVERIDADE / IMPACTO
// ==============================================================================

export const SECURITY_CATEGORIES = [
  'hardening',
  'autenticacao',
  'criptografia',
  'banco_de_dados',
  'conformidade',
  'rede_api',
  'auditoria'
] as const;

export type SecurityCategory = typeof SECURITY_CATEGORIES[number];

export const SECURITY_SEVERITIES = [
  'critico',
  'alto',
  'medio',
  'baixo',
  'informativo'
] as const;

export type SecuritySeverity = typeof SECURITY_SEVERITIES[number];

export const SECURITY_STATUSES = [
  'ativo',
  'rascunho',
  'arquivado'
] as const;

export type SecurityStatus = typeof SECURITY_STATUSES[number];

// ==============================================================================
// 3. SCHEMAS ZOD PARA ARQUIVOS
// ==============================================================================

export const SecurityFilePathSchema = z.string()
  .min(1, 'O caminho do arquivo não pode ser vazio.')
  .max(255, 'O caminho do arquivo deve ter no máximo 255 caracteres.')
  .refine(p => !p.includes('..'), 'Path traversal proibido: caminho não pode conter "..".')
  .refine(p => !p.startsWith('/') && !p.startsWith('\\'), 'Caminho deve ser relativo ao diretório da tecnologia de segurança.')
  .refine(p => !/^[a-zA-Z]:/.test(p), 'Caminhos absolutos do Windows são proibidos.')
  .refine(p => !p.includes('\0'), 'Caracteres nulos são proibidos.')
  .refine(p => {
    const ext = p.substring(p.lastIndexOf('.')).toLowerCase();
    return ALLOWED_SECURITY_EXTENSIONS.includes(ext as any);
  }, `Extensão de arquivo não permitida. Extensões válidas: ${ALLOWED_SECURITY_EXTENSIONS.join(', ')}`);

export const SecurityFileContentSchema = z.string()
  .max(MAX_SECURITY_FILE_SIZE_BYTES, `Arquivo excede o limite máximo permitido de ${MAX_SECURITY_FILE_SIZE_BYTES / 1024} KB.`);

export const SecurityFileZodSchema = z.object({
  id: z.string().min(1),
  securityId: z.string().min(1),
  path: SecurityFilePathSchema,
  name: z.string().min(1).max(100),
  extension: z.string().max(10),
  contentType: z.string().max(100),
  sizeBytes: z.number().nonnegative(),
  sha256: z.string().length(64),
  content: SecurityFileContentSchema,
  version: z.string().default('1.0.0'),
  createdAt: z.string(),
  updatedAt: z.string(),
  deletedAt: z.string().nullable().optional()
});

export type SecurityFile = z.infer<typeof SecurityFileZodSchema>;

// ==============================================================================
// 4. SCHEMAS ZOD PARA ITENS DE SEGURANÇA
// ==============================================================================

export const SecurityTagSchema = z.string()
  .min(1, 'Tag não pode ser vazia')
  .max(40, 'Tag deve ter no máximo 40 caracteres')
  .regex(/^[a-z0-9_#-]+$/i, 'Tag deve conter apenas letras, números, hífen, underline ou hash');

export const SecurityItemZodSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(2, 'O nome deve ter no mínimo 2 caracteres.').max(120),
  slug: z.string().min(2).max(100).regex(/^[a-z0-9-]+$/, 'Slug deve conter apenas letras minúsculas, números e hífens.'),
  description: z.string().min(5, 'A descrição deve ter no mínimo 5 caracteres.').max(1000),
  category: z.enum(SECURITY_CATEGORIES).default('aplicacao'),
  severity: z.enum(SECURITY_SEVERITIES).default('alto'),
  tags: z.array(SecurityTagSchema).default([]),
  status: z.enum(SECURITY_STATUSES).default('ativo'),
  complianceStandards: z.array(z.string()).default([]),
  mitigatedVulnerabilities: z.array(z.string()).default([]),
  files: z.array(SecurityFileZodSchema).default([]),
  createdAt: z.string(),
  updatedAt: z.string()
});

export type SecurityItem = z.infer<typeof SecurityItemZodSchema>;

// ==============================================================================
// 5. AUDITORIA DE SEGURANÇA
// ==============================================================================

export const SecurityAuditLogActionSchema = z.enum([
  'created',
  'updated',
  'deleted',
  'tag_added',
  'tag_removed',
  'file_created',
  'file_updated',
  'file_deleted',
  'file_restored'
]);

export const SecurityAuditLogZodSchema = z.object({
  id: z.string().min(1),
  securityId: z.string().min(1),
  actor: z.string().min(1),
  action: SecurityAuditLogActionSchema,
  details: z.string().min(1),
  metadata: z.record(z.string(), z.any()).optional(),
  createdAt: z.string()
});

export type SecurityAuditLog = z.infer<typeof SecurityAuditLogZodSchema>;
