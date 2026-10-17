/**
 * TIPOS, ENUMS E SCHEMAS ZOD PARA O MÓDULO DE CONTROLES DE SEGURANÇA (SECURITY CONTROLS)
 * Central Privada de Segurança Corporativa — Firstsys
 * Entidades independentes: security_controls, security_control_evidence, security_control_exceptions, security_audit_events
 */

import { z } from 'zod';

// ==============================================================================
// 1. ENUMS E CONSTANTES DE CATEGORIA, STATUS E SEVERIDADE
// ==============================================================================

export const SECURITY_CONTROL_CATEGORIES = [
  'rede',
  'trafego',
  'api',
  'autenticacao',
  'dados',
  'infraestrutura',
  'aplicacao',
  'monitoramento',
  'incidentes',
  'governanca'
] as const;

export type SecurityControlCategory = typeof SECURITY_CONTROL_CATEGORIES[number];

export const SECURITY_CONTROL_SEVERITIES = [
  'low',
  'medium',
  'high',
  'critical'
] as const;

export type SecurityControlSeverity = typeof SECURITY_CONTROL_SEVERITIES[number];

export const SECURITY_CONTROL_STATUSES = [
  'planned',
  'in_progress',
  'implemented',
  'verified',
  'not_applicable',
  'exception'
] as const;

export type SecurityControlStatus = typeof SECURITY_CONTROL_STATUSES[number];

export const EVIDENCE_TYPES = [
  'log',
  'metric',
  'config',
  'report',
  'screenshot',
  'code',
  'other'
] as const;

export type SecurityEvidenceType = typeof EVIDENCE_TYPES[number];

export const EXCEPTION_STATUSES = [
  'active',
  'resolved',
  'expired',
  'revoked'
] as const;

export type SecurityExceptionStatus = typeof EXCEPTION_STATUSES[number];

// ==============================================================================
// 2. SCHEMAS DE VALIDAÇÃO ZOD PARA ENTIDADE: security_controls
// ==============================================================================

export const SecurityControlCodeSchema = z.string()
  .min(3, 'Código do controle deve ter ao menos 3 caracteres.')
  .max(30, 'Código do controle deve ter no máximo 30 caracteres.')
  .regex(/^SEC-[A-Za-z0-9_-]+$/, 'Código deve seguir o padrão "SEC-XXX" (ex: SEC-001).');

export const SecurityControlZodSchema = z.object({
  id: z.string().min(1),
  control_code: SecurityControlCodeSchema,
  name: z.string().min(2, 'Nome deve ter ao menos 2 caracteres.').max(200, 'Nome deve ter no máximo 200 caracteres.'),
  category: z.enum(SECURITY_CONTROL_CATEGORIES),
  description: z.string().min(5, 'Descrição deve ter ao menos 5 caracteres.').max(5000, 'Descrição muito longa (máx 5000 chars).'),
  rationale: z.string().min(5, 'Justificativa (rationale) deve ter ao menos 5 caracteres.').max(5000),
  implementation: z.string().min(5, 'Implementação técnica deve ter ao menos 5 caracteres.').max(10000),
  validation_method: z.string().min(5, 'Método de validação deve ter ao menos 5 caracteres.').max(5000),
  evidence: z.string().max(5000).default(''),
  severity: z.enum(SECURITY_CONTROL_SEVERITIES),
  status: z.enum(SECURITY_CONTROL_STATUSES),
  owner: z.string().min(1).max(100).default('SecOps Team'),
  last_verified_at: z.string().nullable().default(null),
  next_review_at: z.string().nullable().default(null),
  created_at: z.string(),
  updated_at: z.string(),
  revision: z.number().int().nonnegative().default(1),
  is_archived: z.boolean().default(false),
  archived_at: z.string().nullable().default(null)
});

export type SecurityControl = z.infer<typeof SecurityControlZodSchema>;

// Input para criação individual
export const SecurityControlCreateInputSchema = z.object({
  control_code: SecurityControlCodeSchema,
  name: z.string().min(2).max(200),
  category: z.enum(SECURITY_CONTROL_CATEGORIES),
  description: z.string().min(5).max(5000),
  rationale: z.string().min(5).max(5000),
  implementation: z.string().min(5).max(10000),
  validation_method: z.string().min(5).max(5000),
  evidence: z.string().max(5000).optional().default(''),
  severity: z.enum(SECURITY_CONTROL_SEVERITIES).default('medium'),
  status: z.enum(SECURITY_CONTROL_STATUSES).default('planned'),
  owner: z.string().max(100).optional().default('SecOps Team'),
  last_verified_at: z.string().nullable().optional().default(null),
  next_review_at: z.string().nullable().optional().default(null),
  idempotency_key: z.string().max(128).optional()
}).strict();

export type SecurityControlCreateInput = z.input<typeof SecurityControlCreateInputSchema>;

// Input para atualização individual com concorrência otimista obrigatória
export const SecurityControlUpdateInputSchema = z.object({
  expected_revision: z.number().int().nonnegative({ message: 'expected_revision é obrigatório para concorrência otimista.' }),
  name: z.string().min(2).max(200).optional(),
  category: z.enum(SECURITY_CONTROL_CATEGORIES).optional(),
  description: z.string().min(5).max(5000).optional(),
  rationale: z.string().min(5).max(5000).optional(),
  implementation: z.string().min(5).max(10000).optional(),
  validation_method: z.string().min(5).max(5000).optional(),
  evidence: z.string().max(5000).optional(),
  severity: z.enum(SECURITY_CONTROL_SEVERITIES).optional(),
  status: z.enum(SECURITY_CONTROL_STATUSES).optional(),
  owner: z.string().max(100).optional(),
  last_verified_at: z.string().nullable().optional(),
  next_review_at: z.string().nullable().optional(),
  idempotency_key: z.string().max(128).optional()
}).strict();

export type SecurityControlUpdateInput = z.input<typeof SecurityControlUpdateInputSchema>;

// ==============================================================================
// 3. ENTIDADE: security_control_evidence
// ==============================================================================

export const SecurityControlEvidenceZodSchema = z.object({
  id: z.string().min(1),
  control_id: z.string().min(1),
  control_code: SecurityControlCodeSchema,
  title: z.string().min(2).max(200),
  description: z.string().min(2).max(5000),
  evidence_type: z.enum(EVIDENCE_TYPES),
  evidence_url: z.string().url().max(1000).optional(),
  evidence_data: z.string().max(100000).optional(), // Dados técnicos sanitizados (sem tokens/chaves)
  hash: z.string().length(64), // SHA-256 da evidência para integridade
  created_at: z.string(),
  created_by: z.string()
});

export type SecurityControlEvidence = z.infer<typeof SecurityControlEvidenceZodSchema>;

export const SecurityControlEvidenceCreateInputSchema = z.object({
  title: z.string().min(2).max(200),
  description: z.string().min(2).max(5000),
  evidence_type: z.enum(EVIDENCE_TYPES).default('report'),
  evidence_url: z.string().url().max(1000).optional(),
  evidence_data: z.string().max(100000).optional(),
  idempotency_key: z.string().max(128).optional()
}).strict();

export type SecurityControlEvidenceCreateInput = z.input<typeof SecurityControlEvidenceCreateInputSchema>;

// ==============================================================================
// 4. ENTIDADE: security_control_exceptions
// ==============================================================================

export const SecurityControlExceptionZodSchema = z.object({
  id: z.string().min(1),
  control_id: z.string().min(1),
  control_code: SecurityControlCodeSchema,
  reason: z.string().min(5).max(5000),
  approved_by: z.string().min(1).max(100),
  risk_accepted: z.boolean(),
  expires_at: z.string(),
  status: z.enum(EXCEPTION_STATUSES),
  created_at: z.string(),
  resolved_at: z.string().nullable().default(null),
  resolved_by: z.string().nullable().default(null),
  resolution_notes: z.string().max(5000).nullable().default(null)
});

export type SecurityControlException = z.infer<typeof SecurityControlExceptionZodSchema>;

export const SecurityControlExceptionCreateInputSchema = z.object({
  reason: z.string().min(5, 'Justificativa do risco aceito é obrigatória.').max(5000),
  approved_by: z.string().min(1).max(100),
  risk_accepted: z.boolean().default(true),
  expires_at: z.string().min(10, 'Data de expiração da exceção é obrigatória.'),
  idempotency_key: z.string().max(128).optional()
}).strict();

export type SecurityControlExceptionCreateInput = z.input<typeof SecurityControlExceptionCreateInputSchema>;

export const SecurityControlExceptionResolveInputSchema = z.object({
  resolution_notes: z.string().min(2, 'Notas de resolução são obrigatórias.').max(5000),
  resolved_by: z.string().min(1).max(100).optional(),
  idempotency_key: z.string().max(128).optional()
}).strict();

export type SecurityControlExceptionResolveInput = z.input<typeof SecurityControlExceptionResolveInputSchema>;

// ==============================================================================
// 5. ENTIDADE: security_audit_events (TRILHA IMUTÁVEL DE AUDITORIA)
// ==============================================================================

export const SecurityAuditEventZodSchema = z.object({
  id: z.string().min(1),
  event_type: z.string().min(1), // ex: 'control.created', 'control.updated', 'control.bulk_updated', 'evidence.created', 'exception.created', 'exception.resolved', 'assessment.run'
  entity_type: z.enum(['security_control', 'security_control_evidence', 'security_control_exception']),
  entity_id: z.string().min(1),
  control_code: z.string().min(1),
  actor: z.string().min(1),
  ip_origin: z.string().default('unknown'),
  diff: z.record(z.string(), z.object({
    old: z.any().optional(),
    new: z.any().optional()
  })).optional(),
  idempotency_key: z.string().optional(),
  created_at: z.string()
});

export type SecurityAuditEvent = z.infer<typeof SecurityAuditEventZodSchema>;

// ==============================================================================
// 6. SCHEMAS DE IMPORTAÇÃO EM MASSA (PREVIEW & COMMIT)
// ==============================================================================

export const SecurityControlImportItemSchema = z.object({
  control_code: SecurityControlCodeSchema,
  name: z.string().min(2).max(200),
  category: z.enum(SECURITY_CONTROL_CATEGORIES),
  description: z.string().min(5).max(5000),
  rationale: z.string().min(5).max(5000),
  implementation: z.string().min(5).max(10000),
  validation_method: z.string().min(5).max(5000),
  evidence: z.string().max(5000).optional().default(''),
  severity: z.enum(SECURITY_CONTROL_SEVERITIES).default('medium'),
  status: z.enum(SECURITY_CONTROL_STATUSES).default('planned'),
  owner: z.string().max(100).optional().default('SecOps Team'),
  last_verified_at: z.string().nullable().optional().default(null),
  next_review_at: z.string().nullable().optional().default(null)
}).strict();

export type SecurityControlImportItem = z.input<typeof SecurityControlImportItemSchema>;

export interface SecurityControlImportDiff {
  control_code: string;
  name: string;
  action: 'create' | 'update' | 'unchanged';
  changed_fields: string[];
  diff?: Record<string, { old?: any; new?: any }>;
}

export interface SecurityControlImportPreviewResult {
  ok: boolean;
  total_items: number;
  valid_count: number;
  invalid_count: number;
  to_create_count: number;
  to_update_count: number;
  unchanged_count: number;
  validation_errors: Array<{
    index: number;
    control_code?: string;
    errors: string[];
  }>;
  items_diff: SecurityControlImportDiff[];
  summary: string;
}

// ==============================================================================
// 7. POSTURA DE SEGURANÇA AGREGADA (SEM DADOS SENSÍVEIS)
// ==============================================================================

export interface SecurityPostureSummary {
  total_controls: number;
  active_controls: number;
  archived_controls: number;
  by_status: Record<SecurityControlStatus, number>;
  by_severity: Record<SecurityControlSeverity, number>;
  by_category: Record<SecurityControlCategory, number>;
  compliance_rate_percent: number; // ((implemented + verified) / active) * 100
  overdue_reviews_count: number; // controles cujo next_review_at < now
  active_exceptions_count: number;
  total_evidences_count: number;
  generated_at: string;
}
