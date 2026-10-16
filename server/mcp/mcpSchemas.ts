/**
 * SCHEMAS E VALIDAÇÕES ESTRITAS ZOD PARA FERRAMENTAS MCP ZATTEN
 * Central Privada de Conexões Zatten — Firstsys
 * Em conformidade rigorosa com a especificação non-deploy/mcp-zatten.md
 */

import { z } from 'zod';

// Validação de número de telefone (apenas dígitos, DDI, entre 10 e 15 caracteres)
export const PhoneNumberSchema = z.string()
  .trim()
  .regex(/^\d{10,15}$/, 'Número de telefone deve conter apenas dígitos (com DDI e DDD) entre 10 e 15 caracteres.');

// Validação de Path de Webhook (apenas minúsculas, números e hífen)
export const HookPathSchema = z.string()
  .trim()
  .min(1, 'Path não pode ser vazio.')
  .max(100, 'Path deve ter no máximo 100 caracteres.')
  .regex(/^[a-z0-9-]+$/, 'Path deve conter exclusivamente letras minúsculas, números e hífens.');

// Validação de Slug de Propriedade
export const SlugSchema = z.string()
  .trim()
  .min(1, 'Slug não pode ser vazio.')
  .max(100, 'Slug deve ter no máximo 100 caracteres.')
  .regex(/^[a-z0-9_-]+$/i, 'Slug deve conter apenas letras, números, sublinhados ou hífens.');

// 1. zatten_properties_get
export const ZattenPropertiesGetSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional()
}).strict();

// 2. zatten_properties_slug_values_get
export const ZattenPropertiesSlugValuesGetSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional(),
  property_slug: SlugSchema
}).strict();

// 3. zatten_leads_leadnumber_notification_post
export const ZattenLeadsLeadNumberNotificationPostSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional(),
  lead_number: PhoneNumberSchema,
  leadNumber: PhoneNumberSchema.optional(),
  title: z.string().max(100, 'Título da notificação não pode exceder 100 caracteres.').optional(),
  body: z.string().max(500, 'Corpo da notificação não pode exceder 500 caracteres.').optional()
}).strict().superRefine((data, ctx) => {
  const totalLength = (data.title?.length || 0) + (data.body?.length || 0);
  if (totalLength > 4000) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'O payload de notificação excede o limite máximo permitido de 4.000 caracteres.'
    });
  }
});

// 4. zatten_automations_trigger_post
export const ZattenAutomationsTriggerPostSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional(),
  lead_id: z.string().min(1, 'lead_id obrigatório').max(100)
}).strict();

// 5. zatten_flows_trigger_post
export const TriggerTypeEnum = z.enum([
  'lead.first_message',
  'lead.column_changed',
  'lead.tag_added',
  'lead.tag_removed',
  'lead.assignee_changed',
  'lead.conversation_closed',
  'webhook.inbound',
  'lead.ai_toggled'
]);

export const ZattenFlowsTriggerPostSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional(),
  lead_number: PhoneNumberSchema.optional(),
  leadNumber: PhoneNumberSchema.optional(),
  lead_id: z.string().min(1).max(100).optional(),
  trigger_type: TriggerTypeEnum,
  trigger_event: z.record(z.string(), z.unknown()).optional(),
  idempotency_key: z.string().max(128).optional()
}).strict().refine(
  data => {
    const hasNum = !!(data.lead_number || data.leadNumber);
    const hasId = !!data.lead_id;
    return (hasNum && !hasId) || (!hasNum && hasId);
  },
  { message: 'É obrigatório informar exatamente um entre lead_number e lead_id (nunca ambos nem nenhum).' }
);

// 6. zatten_hooks_path_post
export const ZattenHooksPathPostSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional(),
  path: HookPathSchema,
  lead_number: PhoneNumberSchema.optional(),
  leadNumber: PhoneNumberSchema.optional(),
  lead_id: z.string().min(1).max(100).optional(),
  idempotency_key: z.string().max(128).optional(),
  payload: z.union([z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional()
}).strict().refine(
  data => {
    const hasNum = !!(data.lead_number || data.leadNumber);
    const hasId = !!data.lead_id;
    return (hasNum && !hasId) || (!hasNum && hasId);
  },
  { message: 'É obrigatório informar exatamente um entre lead_number e lead_id (nunca ambos nem nenhum).' }
);

// 7. zatten_agent_config_get
export const ZattenAgentConfigGetSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional()
}).strict();

// 8. zatten_agent_config_update
export const ZattenAgentConfigUpdateSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional(),
  expected_revision: z.string().min(1, 'expected_revision é obrigatório para concorrência').max(200),
  template_patch: z.record(z.string(), z.unknown()),
  reason: z.string().min(1, 'reason da alteração é obrigatório').max(500)
}).strict().refine(
  data => {
    const patch = data.template_patch as Record<string, any>;
    if (patch.publish_agent === true || patch.publish_agent === 'true') return false;
    if (patch.submit_meta_templates === true || patch.submit_meta_templates === 'true') return false;
    return true;
  },
  { message: 'Publicação automática não é permitida. Não defina publish_agent ou submit_meta_templates como true.' }
);

// 9. zatten_leads_leadnumber_assignee_patch (Melhoria)
export const ZattenLeadsLeadNumberAssigneePatchSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional(),
  leadNumber: PhoneNumberSchema.optional(),
  lead_number: PhoneNumberSchema.optional(),
  department_id: z.string().min(1, 'department_id é obrigatório').max(100),
  user_email: z.string().email('E-mail do usuário inválido').max(150).optional(),
  user_id: z.string().min(1).max(100).optional()
}).strict().refine(
  data => {
    // Exigir telefone em leadNumber ou lead_number
    if (!data.leadNumber && !data.lead_number) return false;
    // Aceitar no máximo um entre user_email e user_id
    if (data.user_email && data.user_id) return false;
    return true;
  },
  { message: 'Informe leadNumber e no máximo um entre user_email e user_id (se nenhum for informado, será usado o rodízio do departamento).' }
);

// 10. zatten_leads_leadnumber_toggle_attendant_response_post (Melhoria)
export const ZattenLeadsLeadNumberAiPatchSchema = z.object({
  connection_id: z.string().max(100).optional(),
  connectionId: z.string().max(100).optional(),
  leadNumber: PhoneNumberSchema.optional(),
  lead_number: PhoneNumberSchema.optional(),
  enabled: z.boolean(),
  pause_minutes: z.number().int().min(1).max(10080).optional()
}).strict().refine(
  data => {
    if (!data.leadNumber && !data.lead_number) return false;
    // pause_minutes só é permitido quando enabled: false
    if (data.enabled && data.pause_minutes !== undefined) return false;
    return true;
  },
  { message: 'pause_minutes só é permitido quando enabled for false (pausar atendimento por 1 até 10.080 minutos).' }
);

// ==============================================================================
// 11. SCHEMAS DE FERRAMENTAS MCP DE SKILLS DE IA (firstsys_skills_*)
// ==============================================================================

// 11.1 firstsys_skills_list
export const SkillListSchema = z.object({
  category: z.string().max(50).optional(),
  query: z.string().max(100).optional(),
  origin: z.string().max(50).optional(),
  status: z.string().max(50).optional(),
  installed_only: z.boolean().optional(),
  page: z.number().int().min(1).default(1).optional(),
  limit: z.number().int().min(1).max(50).default(20).optional()
}).strict();

// 11.2 firstsys_skills_get
export const SkillGetSchema = z.object({
  skill_id: z.string().min(1, 'skill_id ou slug é obrigatório').max(100)
}).strict();

// 11.3 firstsys_skills_create
export const SkillCreateSchema = z.object({
  name: z.string().min(2, 'Nome da skill deve ter no mínimo 2 caracteres').max(100),
  description: z.string().min(5, 'Descrição deve ter no mínimo 5 caracteres').max(500),
  category: z.string().max(50).default('geral'),
  tags: z.array(z.string().max(30)).max(15).optional(),
  license: z.string().max(100).optional(),
  version: z.string().regex(/^\d+\.\d+\.\d+/, 'Versão semântica inválida (ex: 1.0.0)').optional(),
  skill_md_content: z.string().min(10, 'Conteúdo de SKILL.md obrigatório').max(100000).optional()
}).strict();

// 11.4 firstsys_skills_update
export const SkillUpdateSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  name: z.string().min(2).max(100).optional(),
  description: z.string().max(500).optional(),
  category: z.string().max(50).optional(),
  tags: z.array(z.string().max(30)).max(15).optional(),
  status: z.enum(['rascunho', 'ativa', 'arquivada', 'descontinuada', 'active', 'inactive']).optional(),
  version: z.string().regex(/^\d+\.\d+\.\d+/).optional(),
  license: z.string().max(100).optional()
}).strict();

// 11.5 firstsys_skills_delete
export const SkillDeleteSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  confirm: z.boolean().refine(val => val === true, {
    message: 'A exclusão de uma skill requer confirm: true para evitar perdas acidentais.'
  }),
  hard_delete: z.boolean().default(false).optional()
}).strict();

// 11.6 firstsys_skills_install
export const SkillInstallSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  context_type: z.enum(['agent', 'connection', 'project', 'mcp', 'environment']).default('connection').optional(),
  context_id: z.string().max(100).default('conn_coolify_principal').optional(),
  context_name: z.string().max(150).default('Conexão Padrão').optional(),
  pinned_version: z.string().regex(/^\d+\.\d+\.\d+/).optional(),
  config: z.record(z.string(), z.any()).optional()
}).strict();

// 11.7 firstsys_skills_uninstall
export const SkillUninstallSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  context_id: z.string().max(100).optional(),
  installation_id: z.string().max(100).optional()
}).strict();

// 11.8 firstsys_skill_files_list
export const SkillFilesListSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  include_deleted: z.boolean().default(false).optional()
}).strict();

// 11.9 firstsys_skill_files_get
export const SkillFilesGetSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  path: z.string().min(1, 'path do arquivo é obrigatório').max(255)
}).strict();

// 11.10 firstsys_skill_files_create
export const SkillFilesCreateSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  path: z.string().min(1, 'path relativo é obrigatório').max(255),
  content: z.string().max(1000000, 'Arquivo excede 1MB')
}).strict();

// 11.11 firstsys_skill_files_update
export const SkillFilesUpdateSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  path: z.string().min(1, 'path relativo é obrigatório').max(255),
  content: z.string().max(1000000, 'Arquivo excede 1MB')
}).strict();

// 11.12 firstsys_skill_files_delete
export const SkillFilesDeleteSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  path: z.string().min(1, 'path relativo é obrigatório').max(255),
  permanent: z.boolean().default(false).optional()
}).strict();

// 11.13 firstsys_skill_files_restore
export const SkillFilesRestoreSchema = z.object({
  skill_id: z.string().min(1, 'skill_id é obrigatório').max(100),
  path: z.string().min(1, 'path relativo é obrigatório').max(255)
}).strict();

// 11.14 firstsys_skills_import_preview
export const SkillImportPreviewSchema = z.object({
  repo_url: z.string().url('URL inválida').max(500)
}).strict();

// 11.15 firstsys_skills_import_from_git
export const SkillImportFromGitSchema = z.object({
  repo_url: z.string().url('URL inválida').max(500),
  selected_paths: z.array(z.string().max(255)).min(1, 'Selecione ao menos um arquivo'),
  skill_name: z.string().max(100).optional(),
  category: z.string().max(50).optional(),
  tags: z.array(z.string().max(30)).optional(),
  license: z.string().max(100).optional()
}).strict();

// 11.16 firstsys_skills_import_status
export const SkillImportStatusSchema = z.object({
  skill_id: z.string().min(1).max(100)
}).strict();

// 11.17 firstsys_skills_sync_preview
export const SkillSyncPreviewSchema = z.object({
  skill_id: z.string().min(1).max(100)
}).strict();

// 11.18 firstsys_skills_sync_from_git
export const SkillSyncFromGitSchema = z.object({
  skill_id: z.string().min(1).max(100),
  confirm: z.boolean().refine(v => v === true, {
    message: 'A sincronização com repositório remoto exige confirm: true'
  })
}).strict();

// 11.19 firstsys_skills_versions_list
export const SkillVersionsListSchema = z.object({
  skill_id: z.string().min(1).max(100)
}).strict();

// 11.20 firstsys_skills_versions_get
export const SkillVersionsGetSchema = z.object({
  skill_id: z.string().min(1).max(100),
  version: z.string().min(1).max(20)
}).strict();

// 11.21 firstsys_skills_versions_compare
export const SkillVersionsCompareSchema = z.object({
  skill_id: z.string().min(1).max(100),
  version_a: z.string().min(1).max(20),
  version_b: z.string().min(1).max(20)
}).strict();

// 11.22 firstsys_skills_versions_restore
export const SkillVersionsRestoreSchema = z.object({
  skill_id: z.string().min(1).max(100),
  version: z.string().min(1).max(20),
  confirm: z.boolean().refine(v => v === true, {
    message: 'O rollback de versão exige confirm: true'
  })
}).strict();

// 11.23 firstsys_skills_audit_list
export const SkillAuditListSchema = z.object({
  skill_id: z.string().min(1).max(100),
  limit: z.number().int().min(1).max(100).default(50).optional()
}).strict();

// 11.24 firstsys_skills_dependencies_list
export const SkillDependenciesListSchema = z.object({
  skill_id: z.string().min(1).max(100)
}).strict();

// 11.25 firstsys_skills_permissions_get
export const SkillPermissionsGetSchema = z.object({
  skill_id: z.string().min(1).max(100)
}).strict();

// 11.26 firstsys_skills_permissions_update
export const SkillPermissionsUpdateSchema = z.object({
  skill_id: z.string().min(1).max(100),
  permissions: z.array(z.string().max(50)).max(30)
}).strict();

