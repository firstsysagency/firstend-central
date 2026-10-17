/**
 * GERENCIADOR DE DADOS E PERSISTÊNCIA: CONTROLES DE SEGURANÇA CORPORATIVA (SECURITY CONTROLS)
 * Central Privada Firstsys — Módulo Próprio de Segurança
 * Gerencia security_controls, security_control_evidence, security_control_exceptions, security_audit_events
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import process from 'node:process';
import {
  SecurityControl,
  SecurityControlCreateInput,
  SecurityControlUpdateInput,
  SecurityControlEvidence,
  SecurityControlEvidenceCreateInput,
  SecurityControlException,
  SecurityControlExceptionCreateInput,
  SecurityControlExceptionResolveInput,
  SecurityAuditEvent,
  SecurityControlImportItem,
  SecurityControlImportItemSchema,
  SecurityControlImportPreviewResult,
  SecurityPostureSummary,
  SecurityControlStatus,
  SecurityControlSeverity,
  SecurityControlCategory
} from './securityControlsTypes.js';
import { SEED_100_SECURITY_CONTROLS } from './seed100Controls.js';

const DB_PATH = path.join(process.cwd(), 'server', 'db.json');

// Interface do DB com as entidades de controles de segurança
export interface DbSecurityControlsSchema {
  security_controls?: SecurityControl[];
  security_control_evidence?: SecurityControlEvidence[];
  security_control_exceptions?: SecurityControlException[];
  security_audit_events?: SecurityAuditEvent[];
  security_idempotency_cache?: Record<string, { timestamp: string; result: any }>;
  [key: string]: any;
}

// ==============================================================================
// 1. LEITURA E GRAVAÇÃO DO BANCO DE DADOS
// ==============================================================================

export function readDb(): DbSecurityControlsSchema {
  try {
    if (!fs.existsSync(DB_PATH)) {
      return {};
    }
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('❌ [SecurityControlsStore] Falha ao ler db.json:', err);
    return {};
  }
}

export function writeDb(data: DbSecurityControlsSchema): void {
  try {
    const serialized = JSON.stringify(data, null, 2);
    const tempPath = `${DB_PATH}.tmp.${crypto.randomBytes(4).toString('hex')}`;
    fs.writeFileSync(tempPath, serialized, 'utf8');
    fs.renameSync(tempPath, DB_PATH);
  } catch (err) {
    console.error('❌ [SecurityControlsStore] Falha ao salvar db.json:', err);
    throw new Error('Falha ao persistir alterações no banco de dados de segurança.');
  }
}

// ==============================================================================
// 2. AUDITORIA IMUTÁVEL (security_audit_events)
// ==============================================================================

export function recordAuditEvent(params: {
  event_type: string;
  entity_type: 'security_control' | 'security_control_evidence' | 'security_control_exception';
  entity_id: string;
  control_code: string;
  actor: string;
  ip_origin?: string;
  diff?: Record<string, { old?: any; new?: any }>;
  idempotency_key?: string;
}): SecurityAuditEvent {
  const db = readDb();
  if (!db.security_audit_events) {
    db.security_audit_events = [];
  }

  // Sanitizar diff para garantir que nenhum segredo seja gravado
  const sanitizedDiff: Record<string, { old?: any; new?: any }> = {};
  if (params.diff) {
    for (const [key, val] of Object.entries(params.diff)) {
      const lower = key.toLowerCase();
      if (lower.includes('secret') || lower.includes('key') || lower.includes('token') || lower.includes('password')) {
        sanitizedDiff[key] = { old: '[REDACTED]', new: '[REDACTED]' };
      } else {
        sanitizedDiff[key] = val;
      }
    }
  }

  const event: SecurityAuditEvent = {
    id: `sec_aud_${crypto.randomUUID()}`,
    event_type: params.event_type,
    entity_type: params.entity_type,
    entity_id: params.entity_id,
    control_code: params.control_code,
    actor: params.actor || 'system',
    ip_origin: params.ip_origin || 'internal',
    diff: Object.keys(sanitizedDiff).length > 0 ? sanitizedDiff : undefined,
    idempotency_key: params.idempotency_key,
    created_at: new Date().toISOString()
  };

  db.security_audit_events.push(event);
  writeDb(db);
  return event;
}

// ==============================================================================
// 3. INICIALIZAÇÃO / SEED DOS 100 CONTROLES
// ==============================================================================

export function seedInitial100ControlsIfEmpty(): void {
  const db = readDb();
  if (!db.security_controls || db.security_controls.length === 0) {
    console.log('🛡️ [SecurityControls] Inicializando os 100 Controles de Segurança Corporativa (SEC-001 a SEC-100)...');
    
    const now = new Date().toISOString();
    const seededControls: SecurityControl[] = SEED_100_SECURITY_CONTROLS.map((item, idx) => ({
      id: `sec_ctrl_${(idx + 1).toString().padStart(3, '0')}_${crypto.randomBytes(4).toString('hex')}`,
      control_code: item.control_code,
      name: item.name,
      category: item.category,
      description: item.description,
      rationale: item.rationale,
      implementation: item.implementation,
      validation_method: item.validation_method,
      evidence: item.evidence || '',
      severity: item.severity,
      status: item.status,
      owner: item.owner || 'SecOps Team',
      last_verified_at: item.last_verified_at || now,
      next_review_at: item.next_review_at || new Date(Date.now() + 90 * 86400000).toISOString(),
      created_at: now,
      updated_at: now,
      revision: 1,
      is_archived: false,
      archived_at: null
    }));

    db.security_controls = seededControls;
    if (!db.security_control_evidence) db.security_control_evidence = [];
    if (!db.security_control_exceptions) db.security_control_exceptions = [];
    if (!db.security_audit_events) db.security_audit_events = [];

    // Registrar evento de auditoria da carga inicial
    db.security_audit_events.push({
      id: `sec_aud_init_${crypto.randomUUID()}`,
      event_type: 'controls.initial_seed',
      entity_type: 'security_control',
      entity_id: 'all_100',
      control_code: 'SEC-001..SEC-100',
      actor: 'system:bootstrap',
      ip_origin: '127.0.0.1',
      created_at: now
    });

    writeDb(db);
    console.log(`✅ [SecurityControls] 100 Controles de Segurança Corporativa ativos e persistidos no banco de dados!`);
  }
}

// Auto-executar semente se banco estiver vazio
seedInitial100ControlsIfEmpty();

// ==============================================================================
// 4. CONSULTA E RECUPERAÇÃO DE CONTROLES
// ==============================================================================

export function listSecurityControls(filters: {
  category?: SecurityControlCategory;
  status?: SecurityControlStatus;
  severity?: SecurityControlSeverity;
  owner?: string;
  search?: string;
  include_archived?: boolean;
  limit?: number;
  offset?: number;
} = {}): { controls: SecurityControl[]; total: number; offset: number; limit: number } {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  let controls = (db.security_controls || []);

  if (!filters.include_archived) {
    controls = controls.filter(c => !c.is_archived);
  }

  if (filters.category) {
    controls = controls.filter(c => c.category === filters.category);
  }

  if (filters.status) {
    controls = controls.filter(c => c.status === filters.status);
  }

  if (filters.severity) {
    controls = controls.filter(c => c.severity === filters.severity);
  }

  if (filters.owner) {
    const ownerQuery = filters.owner.toLowerCase();
    controls = controls.filter(c => c.owner.toLowerCase().includes(ownerQuery));
  }

  if (filters.search) {
    const q = filters.search.toLowerCase();
    controls = controls.filter(c =>
      c.control_code.toLowerCase().includes(q) ||
      c.name.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      c.rationale.toLowerCase().includes(q) ||
      c.implementation.toLowerCase().includes(q)
    );
  }

  const total = controls.length;
  const offset = Math.max(0, filters.offset || 0);
  const limit = Math.min(100, Math.max(1, filters.limit || 50));
  const paginated = controls.slice(offset, offset + limit);

  return {
    controls: paginated,
    total,
    offset,
    limit
  };
}

export function getSecurityControl(idOrCode: string): SecurityControl | null {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  const controls = db.security_controls || [];
  const query = idOrCode.trim();

  const found = controls.find(c => c.id === query || c.control_code.toUpperCase() === query.toUpperCase());
  return found || null;
}

// ==============================================================================
// 5. CRIAÇÃO, EDIÇÃO E CONCORRÊNCIA OTIMISTA
// ==============================================================================

export function createSecurityControl(
  input: SecurityControlCreateInput,
  actor: string = 'system',
  ip: string = 'internal',
  idempotencyKey?: string
): SecurityControl {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  if (!db.security_controls) db.security_controls = [];

  // Tratamento de Idempotência
  if (idempotencyKey) {
    if (!db.security_idempotency_cache) db.security_idempotency_cache = {};
    const cached = db.security_idempotency_cache[idempotencyKey];
    if (cached) {
      return cached.result as SecurityControl;
    }
  }

  // Validar código único
  const existing = db.security_controls.find(c => c.control_code.toUpperCase() === input.control_code.toUpperCase());
  if (existing) {
    throw new Error(`Controle de segurança com código "${input.control_code}" já existe (ID: ${existing.id}). Códigos devem ser estritamente únicos.`);
  }

  const now = new Date().toISOString();
  const newControl: SecurityControl = {
    id: `sec_ctrl_${crypto.randomUUID()}`,
    control_code: input.control_code.toUpperCase(),
    name: input.name,
    category: input.category,
    description: input.description,
    rationale: input.rationale,
    implementation: input.implementation,
    validation_method: input.validation_method,
    evidence: input.evidence || '',
    severity: input.severity,
    status: input.status,
    owner: input.owner || 'SecOps Team',
    last_verified_at: input.last_verified_at || null,
    next_review_at: input.next_review_at || null,
    created_at: now,
    updated_at: now,
    revision: 1,
    is_archived: false,
    archived_at: null
  };

  db.security_controls.push(newControl);

  if (idempotencyKey) {
    db.security_idempotency_cache![idempotencyKey] = {
      timestamp: now,
      result: newControl
    };
  }

  writeDb(db);

  recordAuditEvent({
    event_type: 'control.created',
    entity_type: 'security_control',
    entity_id: newControl.id,
    control_code: newControl.control_code,
    actor,
    ip_origin: ip,
    diff: {
      name: { new: newControl.name },
      category: { new: newControl.category },
      severity: { new: newControl.severity },
      status: { new: newControl.status }
    },
    idempotency_key: idempotencyKey
  });

  return newControl;
}

export function updateSecurityControl(
  idOrCode: string,
  patch: SecurityControlUpdateInput,
  actor: string = 'system',
  ip: string = 'internal',
  idempotencyKey?: string
): SecurityControl {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  if (!db.security_controls) db.security_controls = [];

  // Tratamento de Idempotência
  if (idempotencyKey) {
    if (!db.security_idempotency_cache) db.security_idempotency_cache = {};
    const cached = db.security_idempotency_cache[idempotencyKey];
    if (cached) {
      return cached.result as SecurityControl;
    }
  }

  const targetIndex = db.security_controls.findIndex(c =>
    c.id === idOrCode || c.control_code.toUpperCase() === idOrCode.toUpperCase()
  );

  if (targetIndex === -1) {
    throw new Error(`Controle de segurança "${idOrCode}" não encontrado para atualização.`);
  }

  const current = db.security_controls[targetIndex];

  // ============================================================================
  // CONCORRÊNCIA OTIMISTA: validação de expected_revision
  // ============================================================================
  if (current.revision !== patch.expected_revision) {
    const error: any = new Error(
      `Conflito de concorrência detectado no controle "${current.control_code}". ` +
      `Revisão esperada: ${patch.expected_revision}, revisão atual em banco: ${current.revision}. ` +
      `Por favor, recarregue os dados mais recentes antes de aplicar novas alterações.`
    );
    error.status = 409;
    error.code = 'OPTIMISTIC_LOCK_CONFLICT';
    error.currentRevision = current.revision;
    error.expectedRevision = patch.expected_revision;
    throw error;
  }

  // Calcular diff detalhado dos campos que sofreram mutação
  const diff: Record<string, { old: any; new: any }> = {};
  const updatableFields = [
    'name', 'category', 'description', 'rationale',
    'implementation', 'validation_method', 'evidence',
    'severity', 'status', 'owner', 'last_verified_at', 'next_review_at'
  ] as const;

  for (const field of updatableFields) {
    if (patch[field] !== undefined && (patch as any)[field] !== (current as any)[field]) {
      diff[field] = {
        old: (current as any)[field],
        new: (patch as any)[field]
      };
      (current as any)[field] = (patch as any)[field];
    }
  }

  // Atualizar metadados
  current.revision += 1;
  current.updated_at = new Date().toISOString();

  db.security_controls[targetIndex] = current;

  if (idempotencyKey) {
    db.security_idempotency_cache![idempotencyKey] = {
      timestamp: current.updated_at,
      result: current
    };
  }

  writeDb(db);

  recordAuditEvent({
    event_type: 'control.updated',
    entity_type: 'security_control',
    entity_id: current.id,
    control_code: current.control_code,
    actor,
    ip_origin: ip,
    diff: Object.keys(diff).length > 0 ? diff : undefined,
    idempotency_key: idempotencyKey
  });

  return current;
}

export function bulkUpdateSecurityControls(params: {
  control_codes: string[];
  status?: SecurityControlStatus;
  severity?: SecurityControlSeverity;
  owner?: string;
  actor?: string;
  ip?: string;
  idempotency_key?: string;
}): { updated_count: number; updated_codes: string[] } {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  if (!db.security_controls) db.security_controls = [];

  const actor = params.actor || 'system';
  const ip = params.ip || 'internal';
  const codesSet = new Set(params.control_codes.map(c => c.toUpperCase()));
  const updatedCodes: string[] = [];
  const now = new Date().toISOString();

  for (let i = 0; i < db.security_controls.length; i++) {
    const c = db.security_controls[i];
    if (codesSet.has(c.control_code.toUpperCase())) {
      const diff: Record<string, { old: any; new: any }> = {};

      if (params.status && c.status !== params.status) {
        diff.status = { old: c.status, new: params.status };
        c.status = params.status;
      }
      if (params.severity && c.severity !== params.severity) {
        diff.severity = { old: c.severity, new: params.severity };
        c.severity = params.severity;
      }
      if (params.owner && c.owner !== params.owner) {
        diff.owner = { old: c.owner, new: params.owner };
        c.owner = params.owner;
      }

      if (Object.keys(diff).length > 0) {
        c.revision += 1;
        c.updated_at = now;
        updatedCodes.push(c.control_code);

        recordAuditEvent({
          event_type: 'control.bulk_updated',
          entity_type: 'security_control',
          entity_id: c.id,
          control_code: c.control_code,
          actor,
          ip_origin: ip,
          diff,
          idempotency_key: params.idempotency_key
        });
      }
    }
  }

  if (updatedCodes.length > 0) {
    writeDb(db);
  }

  return {
    updated_count: updatedCodes.length,
    updated_codes: updatedCodes
  };
}

// ==============================================================================
// 6. IMPORTAÇÃO EM MASSA: PREVIEW & COMMIT
// ==============================================================================

export function importPreviewSecurityControls(rawItems: unknown[]): SecurityControlImportPreviewResult {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  const existingMap = new Map<string, SecurityControl>();
  for (const c of (db.security_controls || [])) {
    existingMap.set(c.control_code.toUpperCase(), c);
  }

  const validationErrors: Array<{ index: number; control_code?: string; errors: string[] }> = [];
  const validItems: SecurityControlImportItem[] = [];
  const diffs: Array<{
    control_code: string;
    name: string;
    action: 'create' | 'update' | 'unchanged';
    changed_fields: string[];
    diff?: Record<string, { old?: any; new?: any }>;
  }> = [];

  let toCreateCount = 0;
  let toUpdateCount = 0;
  let unchangedCount = 0;

  const seenCodesInBatch = new Set<string>();

  for (let idx = 0; idx < rawItems.length; idx++) {
    const raw = rawItems[idx];
    const parsed = SecurityControlImportItemSchema.safeParse(raw);

    if (!parsed.success) {
      const issues = parsed.error.issues.map(i => `${i.path.join('.') || 'root'}: ${i.message}`);
      validationErrors.push({
        index: idx,
        control_code: (raw as any)?.control_code,
        errors: issues
      });
      continue;
    }

    const item = parsed.data;
    const code = item.control_code.toUpperCase();

    if (seenCodesInBatch.has(code)) {
      validationErrors.push({
        index: idx,
        control_code: code,
        errors: [`Código de controle duplicado dentro do próprio lote de importação.`]
      });
      continue;
    }
    seenCodesInBatch.add(code);
    validItems.push(item);

    const existing = existingMap.get(code);
    if (!existing) {
      toCreateCount++;
      diffs.push({
        control_code: code,
        name: item.name,
        action: 'create',
        changed_fields: ['all'],
        diff: {
          name: { new: item.name },
          category: { new: item.category },
          severity: { new: item.severity },
          status: { new: item.status }
        }
      });
    } else {
      const changedFields: string[] = [];
      const itemDiff: Record<string, { old?: any; new?: any }> = {};

      const checkFields = [
        'name', 'category', 'description', 'rationale',
        'implementation', 'validation_method', 'evidence',
        'severity', 'status', 'owner'
      ] as const;

      for (const f of checkFields) {
        if ((item as any)[f] !== undefined && (item as any)[f] !== (existing as any)[f]) {
          changedFields.push(f);
          itemDiff[f] = {
            old: (existing as any)[f],
            new: (item as any)[f]
          };
        }
      }

      if (changedFields.length > 0) {
        toUpdateCount++;
        diffs.push({
          control_code: code,
          name: item.name,
          action: 'update',
          changed_fields: changedFields,
          diff: itemDiff
        });
      } else {
        unchangedCount++;
        diffs.push({
          control_code: code,
          name: item.name,
          action: 'unchanged',
          changed_fields: []
        });
      }
    }
  }

  const ok = validationErrors.length === 0;
  const summary = ok
    ? `Prévia validada com sucesso: ${rawItems.length} controles analisados (${toCreateCount} novos, ${toUpdateCount} atualizações, ${unchangedCount} inalterados). Nenhuma alteração foi gravada em banco.`
    : `Falha na prévia de importação: ${validationErrors.length} de ${rawItems.length} itens apresentaram erros de validação. Nenhum item foi gravado.`;

  return {
    ok,
    total_items: rawItems.length,
    valid_count: validItems.length,
    invalid_count: validationErrors.length,
    to_create_count: toCreateCount,
    to_update_count: toUpdateCount,
    unchanged_count: unchangedCount,
    validation_errors: validationErrors,
    items_diff: diffs,
    summary
  };
}

export function importCommitSecurityControls(
  items: unknown[],
  idempotencyKey: string | undefined,
  actor: string = 'system',
  ip: string = 'internal'
): { ok: boolean; created_count: number; updated_count: number; unchanged_count: number; message: string } {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  if (!db.security_controls) db.security_controls = [];

  // Idempotência
  if (idempotencyKey) {
    if (!db.security_idempotency_cache) db.security_idempotency_cache = {};
    const cached = db.security_idempotency_cache[idempotencyKey];
    if (cached) {
      return cached.result;
    }
  }

  // 1. Executar prévia para garantir que o lote é 100% válido
  const preview = importPreviewSecurityControls(items);
  if (!preview.ok) {
    throw new Error(
      `Commit de importação cancelado: o lote contém ${preview.invalid_count} itens inválidos. ` +
      `Detalhes: ${JSON.stringify(preview.validation_errors.slice(0, 5))}`
    );
  }

  const now = new Date().toISOString();
  let createdCount = 0;
  let updatedCount = 0;
  let unchangedCount = 0;

  for (const raw of items) {
    const item = SecurityControlImportItemSchema.parse(raw);
    const code = item.control_code.toUpperCase();
    const existingIndex = db.security_controls.findIndex(c => c.control_code.toUpperCase() === code);

    if (existingIndex === -1) {
      // Criação
      const newCtrl: SecurityControl = {
        id: `sec_ctrl_${crypto.randomUUID()}`,
        control_code: code,
        name: item.name,
        category: item.category,
        description: item.description,
        rationale: item.rationale,
        implementation: item.implementation,
        validation_method: item.validation_method,
        evidence: item.evidence || '',
        severity: item.severity,
        status: item.status,
        owner: item.owner || 'SecOps Team',
        last_verified_at: item.last_verified_at || null,
        next_review_at: item.next_review_at || null,
        created_at: now,
        updated_at: now,
        revision: 1,
        is_archived: false,
        archived_at: null
      };

      db.security_controls.push(newCtrl);
      createdCount++;

      recordAuditEvent({
        event_type: 'control.imported_create',
        entity_type: 'security_control',
        entity_id: newCtrl.id,
        control_code: newCtrl.control_code,
        actor,
        ip_origin: ip,
        idempotency_key: idempotencyKey
      });
    } else {
      // Atualização
      const current = db.security_controls[existingIndex];
      const diff: Record<string, { old: any; new: any }> = {};

      const fields = [
        'name', 'category', 'description', 'rationale',
        'implementation', 'validation_method', 'evidence',
        'severity', 'status', 'owner'
      ] as const;

      let changed = false;
      for (const f of fields) {
        if ((item as any)[f] !== undefined && (item as any)[f] !== (current as any)[f]) {
          diff[f] = { old: (current as any)[f], new: (item as any)[f] };
          (current as any)[f] = (item as any)[f];
          changed = true;
        }
      }

      if (changed) {
        current.revision += 1;
        current.updated_at = now;
        db.security_controls[existingIndex] = current;
        updatedCount++;

        recordAuditEvent({
          event_type: 'control.imported_update',
          entity_type: 'security_control',
          entity_id: current.id,
          control_code: current.control_code,
          actor,
          ip_origin: ip,
          diff,
          idempotency_key: idempotencyKey
        });
      } else {
        unchangedCount++;
      }
    }
  }

  const result = {
    ok: true,
    created_count: createdCount,
    updated_count: updatedCount,
    unchanged_count: unchangedCount,
    message: `Importação em massa concluída com sucesso: ${createdCount} criados, ${updatedCount} atualizados e ${unchangedCount} inalterados.`
  };

  if (idempotencyKey) {
    db.security_idempotency_cache![idempotencyKey] = {
      timestamp: now,
      result
    };
  }

  writeDb(db);
  return result;
}

// ==============================================================================
// 7. ARQUIVAMENTO E EXCLUSÃO DEFINITIVA
// ==============================================================================

export function archiveSecurityControl(idOrCode: string, actor: string = 'system', ip: string = 'internal'): SecurityControl {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  const control = (db.security_controls || []).find(c => c.id === idOrCode || c.control_code.toUpperCase() === idOrCode.toUpperCase());

  if (!control) {
    throw new Error(`Controle de segurança "${idOrCode}" não encontrado para arquivamento.`);
  }

  control.is_archived = true;
  control.archived_at = new Date().toISOString();
  control.revision += 1;
  control.updated_at = control.archived_at;

  writeDb(db);

  recordAuditEvent({
    event_type: 'control.archived',
    entity_type: 'security_control',
    entity_id: control.id,
    control_code: control.control_code,
    actor,
    ip_origin: ip
  });

  return control;
}

export function deleteSecurityControl(
  idOrCode: string,
  confirmExplicit: boolean,
  isAdmin: boolean,
  actor: string = 'admin',
  ip: string = 'internal'
): { deleted: boolean; control_code: string; message: string } {
  seedInitial100ControlsIfEmpty();
  if (!isAdmin) {
    throw new Error('Acesso negado: Exclusão definitiva de controles de segurança exige privilégio de Administrador (DONO/ADMIN).');
  }

  if (!confirmExplicit) {
    throw new Error('Exclusão rejeitada: É obrigatório fornecer "confirm: true" explícito para autorizar a exclusão definitiva.');
  }

  const db = readDb();
  const index = (db.security_controls || []).findIndex(c => c.id === idOrCode || c.control_code.toUpperCase() === idOrCode.toUpperCase());

  if (index === -1) {
    throw new Error(`Controle de segurança "${idOrCode}" não encontrado.`);
  }

  const target = db.security_controls![index];
  db.security_controls!.splice(index, 1);
  writeDb(db);

  recordAuditEvent({
    event_type: 'control.deleted_permanently',
    entity_type: 'security_control',
    entity_id: target.id,
    control_code: target.control_code,
    actor,
    ip_origin: ip,
    diff: {
      name: { old: target.name, new: null },
      code: { old: target.control_code, new: null }
    }
  });

  return {
    deleted: true,
    control_code: target.control_code,
    message: `Controle "${target.control_code}" excluído definitivamente com sucesso.`
  };
}

// ==============================================================================
// 8. EVIDÊNCIAS TÉCNICAS (security_control_evidence)
// ==============================================================================

export function createSecurityControlEvidence(
  controlIdOrCode: string,
  input: SecurityControlEvidenceCreateInput,
  actor: string = 'system',
  ip: string = 'internal'
): SecurityControlEvidence {
  const control = getSecurityControl(controlIdOrCode);
  if (!control) {
    throw new Error(`Controle "${controlIdOrCode}" não encontrado para associação de evidência.`);
  }

  const db = readDb();
  if (!db.security_control_evidence) db.security_control_evidence = [];

  // Tratamento de Idempotência
  if (input.idempotency_key) {
    if (!db.security_idempotency_cache) db.security_idempotency_cache = {};
    const cached = db.security_idempotency_cache[input.idempotency_key];
    if (cached) {
      return cached.result as SecurityControlEvidence;
    }
  }

  const payloadForHash = `${control.control_code}|${input.title}|${input.evidence_type}|${input.evidence_data || ''}|${input.evidence_url || ''}`;
  const hash = crypto.createHash('sha256').update(payloadForHash, 'utf8').digest('hex');

  const now = new Date().toISOString();
  const evidence: SecurityControlEvidence = {
    id: `sec_evd_${crypto.randomUUID()}`,
    control_id: control.id,
    control_code: control.control_code,
    title: input.title,
    description: input.description,
    evidence_type: input.evidence_type,
    evidence_url: input.evidence_url,
    evidence_data: input.evidence_data,
    hash,
    created_at: now,
    created_by: actor
  };

  db.security_control_evidence.push(evidence);

  // Atualizar data de verificação do controle
  control.last_verified_at = now;
  control.evidence = input.title;
  control.revision += 1;
  control.updated_at = now;

  const ctrlIndex = db.security_controls!.findIndex(c => c.id === control.id);
  if (ctrlIndex !== -1) {
    db.security_controls![ctrlIndex] = control;
  }

  if (input.idempotency_key) {
    db.security_idempotency_cache![input.idempotency_key] = {
      timestamp: now,
      result: evidence
    };
  }

  writeDb(db);

  recordAuditEvent({
    event_type: 'evidence.created',
    entity_type: 'security_control_evidence',
    entity_id: evidence.id,
    control_code: control.control_code,
    actor,
    ip_origin: ip,
    diff: {
      title: { new: evidence.title },
      evidence_type: { new: evidence.evidence_type },
      hash: { new: evidence.hash }
    },
    idempotency_key: input.idempotency_key
  });

  return evidence;
}

export function listSecurityControlEvidence(controlIdOrCode: string): SecurityControlEvidence[] {
  const control = getSecurityControl(controlIdOrCode);
  if (!control) return [];

  const db = readDb();
  return (db.security_control_evidence || []).filter(e =>
    e.control_id === control.id || e.control_code.toUpperCase() === control.control_code.toUpperCase()
  );
}

// ==============================================================================
// 9. GESTÃO DE EXCEÇÕES E RISCOS ACEITOS (security_control_exceptions)
// ==============================================================================

export function createSecurityControlException(
  controlIdOrCode: string,
  input: SecurityControlExceptionCreateInput,
  actor: string = 'system',
  ip: string = 'internal'
): SecurityControlException {
  const control = getSecurityControl(controlIdOrCode);
  if (!control) {
    throw new Error(`Controle "${controlIdOrCode}" não encontrado para registro de exceção.`);
  }

  const db = readDb();
  if (!db.security_control_exceptions) db.security_control_exceptions = [];

  // Tratamento de Idempotência
  if (input.idempotency_key) {
    if (!db.security_idempotency_cache) db.security_idempotency_cache = {};
    const cached = db.security_idempotency_cache[input.idempotency_key];
    if (cached) {
      return cached.result as SecurityControlException;
    }
  }

  const now = new Date().toISOString();
  const exception: SecurityControlException = {
    id: `sec_exp_${crypto.randomUUID()}`,
    control_id: control.id,
    control_code: control.control_code,
    reason: input.reason,
    approved_by: input.approved_by,
    risk_accepted: input.risk_accepted,
    expires_at: input.expires_at,
    status: 'active',
    created_at: now,
    resolved_at: null,
    resolved_by: null,
    resolution_notes: null
  };

  db.security_control_exceptions.push(exception);

  // Mudar status do controle para 'exception'
  const oldStatus = control.status;
  control.status = 'exception';
  control.revision += 1;
  control.updated_at = now;

  const ctrlIndex = db.security_controls!.findIndex(c => c.id === control.id);
  if (ctrlIndex !== -1) {
    db.security_controls![ctrlIndex] = control;
  }

  if (input.idempotency_key) {
    db.security_idempotency_cache![input.idempotency_key] = {
      timestamp: now,
      result: exception
    };
  }

  writeDb(db);

  recordAuditEvent({
    event_type: 'exception.created',
    entity_type: 'security_control_exception',
    entity_id: exception.id,
    control_code: control.control_code,
    actor,
    ip_origin: ip,
    diff: {
      status: { old: oldStatus, new: 'exception' },
      reason: { new: exception.reason },
      expires_at: { new: exception.expires_at }
    },
    idempotency_key: input.idempotency_key
  });

  return exception;
}

export function listSecurityControlExceptions(filters: {
  status?: string;
  control_code?: string;
} = {}): SecurityControlException[] {
  const db = readDb();
  let list = db.security_control_exceptions || [];

  if (filters.status) {
    list = list.filter(e => e.status === filters.status);
  }

  if (filters.control_code) {
    const q = filters.control_code.toUpperCase();
    list = list.filter(e => e.control_code.toUpperCase() === q);
  }

  return list;
}

export function resolveSecurityControlException(
  exceptionId: string,
  input: SecurityControlExceptionResolveInput,
  actor: string = 'system',
  ip: string = 'internal'
): SecurityControlException {
  const db = readDb();
  const exceptions = db.security_control_exceptions || [];
  const index = exceptions.findIndex(e => e.id === exceptionId);

  if (index === -1) {
    throw new Error(`Exceção de segurança "${exceptionId}" não encontrada.`);
  }

  const exception = exceptions[index];
  if (exception.status === 'resolved') {
    return exception;
  }

  const now = new Date().toISOString();
  exception.status = 'resolved';
  exception.resolved_at = now;
  exception.resolved_by = input.resolved_by || actor;
  exception.resolution_notes = input.resolution_notes;

  exceptions[index] = exception;

  // Restaurar status do controle para 'planned' se ainda estiver como 'exception'
  const control = (db.security_controls || []).find(c => c.id === exception.control_id || c.control_code === exception.control_code);
  if (control && control.status === 'exception') {
    control.status = 'planned';
    control.revision += 1;
    control.updated_at = now;
  }

  writeDb(db);

  recordAuditEvent({
    event_type: 'exception.resolved',
    entity_type: 'security_control_exception',
    entity_id: exception.id,
    control_code: exception.control_code,
    actor,
    ip_origin: ip,
    diff: {
      status: { old: 'active', new: 'resolved' },
      resolution_notes: { new: input.resolution_notes }
    },
    idempotency_key: input.idempotency_key
  });

  return exception;
}

// ==============================================================================
// 10. AVALIAÇÃO DE CONFORMIDADE (ASSESSMENT RUN)
// ==============================================================================

export function runSecurityControlsAssessment(
  controlCodesOrAll: string[] | 'all' = 'all',
  actor: string = 'system',
  ip: string = 'internal'
): {
  evaluated_count: number;
  verified_count: number;
  overdue_count: number;
  evaluated_codes: string[];
  findings: Array<{ control_code: string; name: string; status: string; issue?: string }>;
  timestamp: string;
} {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  const controls = db.security_controls || [];
  const now = new Date();
  const nowIso = now.toISOString();

  let targets = controls.filter(c => !c.is_archived);
  if (Array.isArray(controlCodesOrAll) && controlCodesOrAll.length > 0) {
    const set = new Set(controlCodesOrAll.map(c => c.toUpperCase()));
    targets = targets.filter(c => set.has(c.control_code.toUpperCase()));
  }

  const evaluatedCodes: string[] = [];
  const findings: Array<{ control_code: string; name: string; status: string; issue?: string }> = [];
  let verifiedCount = 0;
  let overdueCount = 0;

  for (const c of targets) {
    evaluatedCodes.push(c.control_code);
    c.last_verified_at = nowIso;
    c.revision += 1;
    c.updated_at = nowIso;

    let issue: string | undefined;
    if (c.next_review_at && new Date(c.next_review_at) < now) {
      issue = `Revisão periódica vencida em ${c.next_review_at}.`;
      overdueCount++;
    }

    if (c.status === 'verified' || c.status === 'implemented') {
      verifiedCount++;
    } else if (c.status === 'planned') {
      issue = issue ? `${issue} Controle ainda planejado (não implementado).` : 'Controle ainda em estado planejado.';
    }

    findings.push({
      control_code: c.control_code,
      name: c.name,
      status: c.status,
      issue
    });
  }

  writeDb(db);

  recordAuditEvent({
    event_type: 'controls.assessment_run',
    entity_type: 'security_control',
    entity_id: 'batch_assessment',
    control_code: evaluatedCodes.length > 5 ? `${evaluatedCodes.length} controles` : evaluatedCodes.join(', '),
    actor,
    ip_origin: ip
  });

  return {
    evaluated_count: evaluatedCodes.length,
    verified_count: verifiedCount,
    overdue_count: overdueCount,
    evaluated_codes: evaluatedCodes,
    findings,
    timestamp: nowIso
  };
}

// ==============================================================================
// 11. POSTURA DE SEGURANÇA AGREGADA (firstsys_security_posture_get)
// ==============================================================================

export function getSecurityPostureSummary(): SecurityPostureSummary {
  seedInitial100ControlsIfEmpty();
  const db = readDb();
  const controls = db.security_controls || [];
  const activeControls = controls.filter(c => !c.is_archived);
  const now = new Date();

  const byStatus: Record<SecurityControlStatus, number> = {
    planned: 0,
    in_progress: 0,
    implemented: 0,
    verified: 0,
    not_applicable: 0,
    exception: 0
  };

  const bySeverity: Record<SecurityControlSeverity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  const byCategory: Record<SecurityControlCategory, number> = {
    rede: 0,
    trafego: 0,
    api: 0,
    autenticacao: 0,
    dados: 0,
    infraestrutura: 0,
    aplicacao: 0,
    monitoramento: 0,
    incidentes: 0,
    governanca: 0
  };

  let overdueReviews = 0;

  for (const c of activeControls) {
    if (byStatus[c.status] !== undefined) byStatus[c.status]++;
    if (bySeverity[c.severity] !== undefined) bySeverity[c.severity]++;
    if (byCategory[c.category] !== undefined) byCategory[c.category]++;

    if (c.next_review_at && new Date(c.next_review_at) < now) {
      overdueReviews++;
    }
  }

  const compliantCount = byStatus.implemented + byStatus.verified;
  const complianceRate = activeControls.length > 0
    ? Math.round((compliantCount / activeControls.length) * 1000) / 10
    : 0;

  const activeExceptions = (db.security_control_exceptions || []).filter(e => e.status === 'active').length;
  const totalEvidences = (db.security_control_evidence || []).length;

  return {
    total_controls: controls.length,
    active_controls: activeControls.length,
    archived_controls: controls.length - activeControls.length,
    by_status: byStatus,
    by_severity: bySeverity,
    by_category: byCategory,
    compliance_rate_percent: complianceRate,
    overdue_reviews_count: overdueReviews,
    active_exceptions_count: activeExceptions,
    total_evidences_count: totalEvidences,
    generated_at: now.toISOString()
  };
}

// ==============================================================================
// 12. CONSULTA DE AUDITORIA (security_audit_events)
// ==============================================================================

export function listSecurityAuditEvents(filters: {
  control_code?: string;
  actor?: string;
  event_type?: string;
  limit?: number;
  offset?: number;
} = {}): { events: SecurityAuditEvent[]; total: number } {
  const db = readDb();
  let events = (db.security_audit_events || []);

  if (filters.control_code) {
    const q = filters.control_code.toUpperCase();
    events = events.filter(e => e.control_code.toUpperCase().includes(q));
  }

  if (filters.actor) {
    const a = filters.actor.toLowerCase();
    events = events.filter(e => e.actor.toLowerCase().includes(a));
  }

  if (filters.event_type) {
    events = events.filter(e => e.event_type === filters.event_type);
  }

  // Ordenar decrescente por data
  events.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  const total = events.length;
  const offset = Math.max(0, filters.offset || 0);
  const limit = Math.min(100, Math.max(1, filters.limit || 50));

  return {
    events: events.slice(offset, offset + limit),
    total
  };
}
