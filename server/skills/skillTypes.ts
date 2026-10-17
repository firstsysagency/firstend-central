import { z } from 'zod';

// ==============================================================================
// 1. CONSTANTES E REGRAS DE POLÍTICA DE ARQUIVOS E SEGURANÇA
// ==============================================================================

export const ALLOWED_TEXT_EXTENSIONS = [
  '.md', '.txt', '.json', '.yaml', '.yml', '.toml',
  '.ts', '.tsx', '.js', '.mjs', '.cjs', '.py',
  '.sh', '.ps1', '.html', '.css', '.sql'
] as const;

export const BLOCKED_OR_SUSPICIOUS_EXTENSIONS = [
  '.env', '.key', '.pem', '.pfx', '.p12', '.crt', '.cer',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.iso', '.zip',
  '.tar', '.gz', '.7z', '.rar', '.sqlite', '.db'
] as const;

export const SENSITIVE_FILE_NAMES = [
  '.env', '.env.local', '.env.production', '.env.development',
  'id_rsa', 'id_ed25519', 'credentials.json', 'service-account.json',
  'secret', 'secrets.json', 'htpasswd', 'shadow'
] as const;

export const MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1 MB por arquivo de texto
export const MAX_TOTAL_SKILL_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB por skill completa

// ==============================================================================
// 2. SCHEMAS ZOD PARA VALIDAÇÃO DE ARQUIVOS
// ==============================================================================

export const SkillFilePathSchema = z.string()
  .min(1, 'O caminho do arquivo não pode ser vazio.')
  .max(255, 'O caminho do arquivo deve ter no máximo 255 caracteres.')
  .refine(p => !p.includes('..'), 'Path traversal proibido: caminho não pode conter "..".')
  .refine(p => !p.startsWith('/') && !p.startsWith('\\'), 'Caminho deve ser relativo ao diretório da skill.')
  .refine(p => !/^[a-zA-Z]:/.test(p), 'Caminhos absolutos do Windows são proibidos.')
  .refine(p => !p.includes('\0'), 'Caracteres nulos são proibidos.')
  .refine(p => {
    const ext = p.substring(p.lastIndexOf('.')).toLowerCase();
    return ALLOWED_TEXT_EXTENSIONS.includes(ext as any);
  }, `Extensão de arquivo não permitida. Extensões válidas: ${ALLOWED_TEXT_EXTENSIONS.join(', ')}`);

export const SkillFileContentSchema = z.string()
  .max(MAX_FILE_SIZE_BYTES, `Arquivo excede o limite máximo permitido de ${MAX_FILE_SIZE_BYTES / 1024} KB.`);

export const SkillFileZodSchema = z.object({
  id: z.string().min(1),
  skillId: z.string().min(1),
  path: SkillFilePathSchema,
  name: z.string().min(1).max(100),
  extension: z.string().max(10),
  contentType: z.string().max(100),
  sizeBytes: z.number().nonnegative(),
  sha256: z.string().length(64),
  content: SkillFileContentSchema,
  origin: z.enum(['local', 'git', 'notion']).default('local'),
  isExecutable: z.boolean().default(false),
  requiresReview: z.boolean().default(false),
  version: z.string().default('1.0.0'),
  createdAt: z.string(),
  updatedAt: z.string(),
  deletedAt: z.string().nullable().optional()
});

export type SkillFile = z.infer<typeof SkillFileZodSchema>;

// ==============================================================================
// 3. SCHEMAS ZOD PARA INSTALAÇÃO POR CONTEXTO
// ==============================================================================

export const SkillInstallationContextTypeSchema = z.enum([
  'agent',
  'connection',
  'project',
  'mcp',
  'environment'
]);

export const SkillInstallationZodSchema = z.object({
  id: z.string().min(1),
  skillId: z.string().min(1),
  contextType: SkillInstallationContextTypeSchema,
  contextId: z.string().min(1).max(100),
  contextName: z.string().min(1).max(150),
  pinnedVersion: z.string().regex(/^\d+\.\d+\.\d+/, 'Versão semântica inválida (ex: 1.0.0)'),
  status: z.enum(['active', 'inactive']).default('active'),
  config: z.record(z.string(), z.any()).default({}),
  grantedPermissions: z.array(z.string()).default([]),
  installedAt: z.string(),
  installedBy: z.string().default('admin')
});

export type SkillInstallation = z.infer<typeof SkillInstallationZodSchema>;

// ==============================================================================
// 4. SCHEMAS ZOD PARA VERSÕES E SNAPSHOTS IMUTÁVEIS
// ==============================================================================

export const SkillVersionZodSchema = z.object({
  id: z.string().min(1),
  skillId: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+/, 'Versão semântica inválida (ex: 1.0.0)'),
  changelog: z.string().max(2000).default('Atualização de arquivos e instruções da skill'),
  snapshotHash: z.string().length(64),
  filesSnapshot: z.array(z.object({
    path: z.string(),
    sha256: z.string().length(64),
    sizeBytes: z.number(),
    name: z.string()
  })),
  createdAt: z.string(),
  createdBy: z.string().default('admin')
});

export type SkillVersion = z.infer<typeof SkillVersionZodSchema>;

// ==============================================================================
// 5. SCHEMA PRINCIPAL DA SKILL
// ==============================================================================

export const SkillOriginSchema = z.enum(['propria', 'importada', 'clonada', 'curada', 'notion']);
export const SkillStatusSchema = z.enum(['rascunho', 'ativa', 'arquivada', 'descontinuada', 'active', 'inactive']);
export const SkillRiskLevelSchema = z.enum(['baixo', 'medio', 'alto']);

export const SkillZodSchema = z.object({
  id: z.string().min(1),
  slug: z.string().min(2).max(100).regex(/^[a-z0-9-_]+$/, 'Slug deve conter apenas letras minúsculas, números, hífens e sublinhados'),
  name: z.string().min(2).max(100),
  description: z.string().min(5).max(500),
  detailedDescription: z.string().max(5000).optional(),
  category: z.string().min(2).max(50),
  tags: z.array(z.string().max(40)).default([]),
  author: z.string().max(100).default('Firstsys AI'),
  origin: SkillOriginSchema.default('propria'),
  status: SkillStatusSchema.default('ativa'),
  installed: z.boolean().default(false), // Retrocompatibilidade Zatten
  version: z.string().regex(/^\d+\.\d+\.\d+/, 'Versão semântica inválida').default('1.0.0'),
  createdAt: z.string(),
  updatedAt: z.string(),
  license: z.string().max(100).default('Proprietária Firstsys'),
  repositoryUrl: z.string().url().max(500).optional().nullable(),
  repositoryOwner: z.string().max(100).optional().nullable(),
  repositoryBranch: z.string().max(100).optional().nullable(),
  repositoryCommitSha: z.string().max(64).optional().nullable(),
  lastSyncAt: z.string().optional().nullable(),
  securityWarnings: z.array(z.string()).default([]),
  riskLevel: SkillRiskLevelSchema.default('baixo'),
  compatibility: z.array(z.string()).default([]),
  dependencies: z.array(z.string()).default([]),
  permissions: z.array(z.string()).default([]),
  files: z.array(SkillFileZodSchema).default([])
});

export type Skill = z.infer<typeof SkillZodSchema>;

// ==============================================================================
// 6. SCHEMAS PARA IMPORTAÇÃO GIT E SECRET SCANNING
// ==============================================================================

export const GitImportUrlSchema = z.string()
  .url('URL inválida')
  .refine(urlStr => {
    try {
      const u = new URL(urlStr);
      const host = u.hostname.toLowerCase();
      // Permitir estritamente GitHub e GitLab públicos
      return (
        host === 'github.com' ||
        host.endsWith('.github.com') ||
        host === 'raw.githubusercontent.com' ||
        host === 'gitlab.com' ||
        host.endsWith('.gitlab.com')
      );
    } catch {
      return false;
    }
  }, 'Apenas repositórios públicos oficiais do GitHub e GitLab são suportados como fontes seguras.');

export interface GitScannedSecretFinding {
  rule: string;
  filePath: string;
  line: number;
  snippetMasked: string;
  severity: 'alta' | 'critica' | 'media';
}

export interface GitImportFileCandidate {
  path: string;
  name: string;
  extension: string;
  sizeBytes: number;
  isExecutable: boolean;
  isIgnored: boolean;
  ignoreReason?: string;
  selected: boolean;
  content?: string;
  sha256?: string;
}

export interface GitImportPreviewResult {
  valid: boolean;
  repoUrl: string;
  owner: string;
  repo: string;
  branch: string;
  commitSha: string;
  license: string;
  detectedName?: string;
  detectedDescription?: string;
  detectedCategory?: string;
  detectedTags?: string[];
  hasSkillMd: boolean;
  files: GitImportFileCandidate[];
  ignoredCount: number;
  totalSizeBytes: number;
  securityFindings: GitScannedSecretFinding[];
  dependenciesDetected: string[];
  riskLevel: 'baixo' | 'medio' | 'alto';
  warningMessage?: string;
}

// ==============================================================================
// 7. SCHEMAS PARA LOGS DE AUDITORIA
// ==============================================================================

export const SkillAuditLogZodSchema = z.object({
  id: z.string().min(1),
  skillId: z.string().min(1),
  actor: z.string().default('sistema'),
  action: z.enum([
    'skill.created',
    'skill.updated',
    'skill.deleted',
    'skill.restored',
    'skill.installed',
    'skill.uninstalled',
    'skill.tag_added',
    'skill.tag_removed',
    'skill.migrated_and_curated',
    'skill.imported_git',
    'skill.synced_git',
    'imported_from_notion',
    'security.scan_completed',
    'file.created',
    'file.updated',
    'file.deleted',
    'file.restored',
    'version.created',
    'version.restored'
  ]),
  details: z.string().max(1000),
  metadata: z.record(z.string(), z.any()).optional(),
  createdAt: z.string()
});

export type SkillAuditLog = z.infer<typeof SkillAuditLogZodSchema>;
