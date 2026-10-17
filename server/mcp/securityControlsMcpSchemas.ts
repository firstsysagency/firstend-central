/**
 * SCHEMAS ZOD PARA AS 15 FERRAMENTAS MCP DE CONTROLES DE SEGURANÇA (SECURITY CONTROLS)
 * Central Privada Firstsys — Módulo Próprio de Segurança
 */

import { z } from 'zod';
import {
  SECURITY_CONTROL_CATEGORIES,
  SECURITY_CONTROL_SEVERITIES,
  SECURITY_CONTROL_STATUSES,
  EVIDENCE_TYPES,
  SecurityControlCodeSchema,
  SecurityControlImportItemSchema
} from '../security/securityControlsTypes.js';

// 1. firstsys_security_controls_list
export const SecurityControlsListMcpSchema = z.object({
  category: z.enum(SECURITY_CONTROL_CATEGORIES).optional().describe('Filtrar por categoria técnica do controle.'),
  status: z.enum(SECURITY_CONTROL_STATUSES).optional().describe('Filtrar por status de implementação do controle.'),
  severity: z.enum(SECURITY_CONTROL_SEVERITIES).optional().describe('Filtrar por nível de severidade ou impacto.'),
  owner: z.string().max(100).optional().describe('Filtrar por time ou responsável.'),
  search: z.string().max(100).optional().describe('Termo de busca textual no código, nome, descrição ou implementação.'),
  include_archived: z.boolean().optional().default(false).describe('Se true, inclui controles arquivados.'),
  limit: z.number().int().min(1).max(100).optional().default(50).describe('Quantidade máxima de registros por página.'),
  offset: z.number().int().min(0).optional().default(0).describe('Deslocamento para paginação.')
}).strict();

// 2. firstsys_security_controls_get
export const SecurityControlsGetMcpSchema = z.object({
  control_id_or_code: z.string().min(1).max(100).describe('ID único ou código do controle (ex: "SEC-001" ou "sec_ctrl_...").')
}).strict();

// 3. firstsys_security_controls_import_preview
export const SecurityControlsImportPreviewMcpSchema = z.object({
  controls: z.array(z.record(z.string(), z.any())).min(1, 'Lote de controles não pode ser vazio.').max(200, 'Máximo de 200 controles por lote.')
    .describe('Array de controles para análise prévia sem gravação.')
}).strict();

// 4. firstsys_security_controls_import_commit
export const SecurityControlsImportCommitMcpSchema = z.object({
  controls: z.array(SecurityControlImportItemSchema).min(1).max(200).describe('Array de controles validados para gravação atômica.'),
  idempotency_key: z.string().min(1).max(128).describe('Chave única de idempotência para evitar importação duplicada.')
}).strict();

// 5. firstsys_security_controls_create
export const SecurityControlsCreateMcpSchema = z.object({
  control_code: SecurityControlCodeSchema.describe('Código único no padrão SEC-XXX (ex: SEC-042).'),
  name: z.string().min(2).max(200).describe('Nome claro e descritivo do controle de segurança.'),
  category: z.enum(SECURITY_CONTROL_CATEGORIES).describe('Categoria técnica à qual o controle pertence.'),
  description: z.string().min(5).max(5000).describe('Descrição detalhada do controle e o que ele assegura.'),
  rationale: z.string().min(5).max(5000).describe('Justificativa de segurança ou risco mitigado.'),
  implementation: z.string().min(5).max(10000).describe('Detalhamento da implementação técnica e arquitetural.'),
  validation_method: z.string().min(5).max(5000).describe('Método de teste ou validação empírica da efetividade do controle.'),
  evidence: z.string().max(5000).optional().default('').describe('Referência ou resumo de evidência técnica associada.'),
  severity: z.enum(SECURITY_CONTROL_SEVERITIES).default('medium').describe('Severidade/Impacto: low, medium, high ou critical.'),
  status: z.enum(SECURITY_CONTROL_STATUSES).default('planned').describe('Status: planned, in_progress, implemented, verified, not_applicable, exception.'),
  owner: z.string().max(100).optional().default('SecOps Team').describe('Time ou operador responsável pela manutenção do controle.'),
  last_verified_at: z.string().nullable().optional().describe('Data da última verificação técnica em formato ISO.'),
  next_review_at: z.string().nullable().optional().describe('Data da próxima revisão periódica obrigatória em formato ISO.'),
  idempotency_key: z.string().max(128).optional().describe('Chave de idempotência para evitar duplicações.')
}).strict();

// 6. firstsys_security_controls_update
export const SecurityControlsUpdateMcpSchema = z.object({
  control_id_or_code: z.string().min(1).max(100).describe('ID ou código único do controle a atualizar.'),
  expected_revision: z.number().int().nonnegative().describe('Revisão esperada do controle para concorrência otimista (evita sobrescritas acidentais).'),
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

// 7. firstsys_security_controls_bulk_update
export const SecurityControlsBulkUpdateMcpSchema = z.object({
  control_codes: z.array(z.string().min(1)).min(1).max(100).describe('Lista de códigos de controle para atualizar em lote (ex: ["SEC-001", "SEC-002"]).'),
  status: z.enum(SECURITY_CONTROL_STATUSES).optional().describe('Novo status para todos os controles informados.'),
  severity: z.enum(SECURITY_CONTROL_SEVERITIES).optional().describe('Nova severidade para todos os controles informados.'),
  owner: z.string().max(100).optional().describe('Novo responsável para todos os controles informados.'),
  idempotency_key: z.string().max(128).optional().describe('Chave de idempotência.')
}).strict();

// 8. firstsys_security_controls_evidence_create
export const SecurityControlsEvidenceCreateMcpSchema = z.object({
  control_id_or_code: z.string().min(1).max(100).describe('ID ou código do controle ao qual vincular a evidência.'),
  title: z.string().min(2).max(200).describe('Título descritivo da evidência de conformidade.'),
  description: z.string().min(2).max(5000).describe('Explicação detalhada do teste, configuração ou prova colhida.'),
  evidence_type: z.enum(EVIDENCE_TYPES).default('report').describe('Tipo de evidência: log, metric, config, report, screenshot, code ou other.'),
  evidence_url: z.string().url().max(1000).optional().describe('URL segura opcional onde a prova completa está hospedada.'),
  evidence_data: z.string().max(100000).optional().describe('Dados técnicos sanitizados da evidência (sem senhas ou tokens).'),
  idempotency_key: z.string().max(128).optional()
}).strict();

// 9. firstsys_security_controls_evidence_list
export const SecurityControlsEvidenceListMcpSchema = z.object({
  control_id_or_code: z.string().min(1).max(100).describe('ID ou código do controle para listar evidências vinculadas.')
}).strict();

// 10. firstsys_security_controls_assessment_run
export const SecurityControlsAssessmentRunMcpSchema = z.object({
  control_codes: z.array(z.string()).optional().describe('Códigos específicos de controle a avaliar ou omitir para avaliar todos os ativos.')
}).strict();

// 11. firstsys_security_posture_get
export const SecurityPostureGetMcpSchema = z.object({}).strict();

// 12. firstsys_security_audit_list
export const SecurityControlsAuditListMcpSchema = z.object({
  control_code: z.string().max(50).optional().describe('Filtrar auditoria por código de controle (ex: SEC-001).'),
  actor: z.string().max(100).optional().describe('Filtrar por usuário ou ator da ação.'),
  event_type: z.string().max(50).optional().describe('Filtrar por tipo de evento (ex: control.created, control.updated).'),
  limit: z.number().int().min(1).max(100).optional().default(50),
  offset: z.number().int().min(0).optional().default(0)
}).strict();

// 13. firstsys_security_exceptions_create
export const SecurityControlsExceptionsCreateMcpSchema = z.object({
  control_id_or_code: z.string().min(1).max(100).describe('ID ou código do controle para registrar a exceção / risco aceito.'),
  reason: z.string().min(5).max(5000).describe('Justificativa técnica e fundamentação do risco aceito.'),
  approved_by: z.string().min(1).max(100).describe('Nome ou identificador do gestor que aprovou a exceção.'),
  risk_accepted: z.boolean().default(true).describe('Confirmação formal de que o risco operacional foi aceito temporariamente.'),
  expires_at: z.string().min(10).describe('Data de expiração da exceção em formato ISO (máximo recomendado: 90 dias).'),
  idempotency_key: z.string().max(128).optional()
}).strict();

// 14. firstsys_security_exceptions_list
export const SecurityControlsExceptionsListMcpSchema = z.object({
  status: z.enum(['active', 'resolved', 'expired', 'revoked']).optional().describe('Filtrar por status da exceção.'),
  control_code: z.string().max(50).optional().describe('Filtrar exceções por código de controle específico.')
}).strict();

// 15. firstsys_security_exceptions_resolve
export const SecurityControlsExceptionsResolveMcpSchema = z.object({
  exception_id: z.string().min(1).max(100).describe('ID da exceção a resolver ou revogar.'),
  resolution_notes: z.string().min(2).max(5000).describe('Notas da resolução e medidas tomadas para sanar o desvio.'),
  resolved_by: z.string().max(100).optional().describe('Nome ou identificador do responsável pela resolução.'),
  idempotency_key: z.string().max(128).optional()
}).strict();
