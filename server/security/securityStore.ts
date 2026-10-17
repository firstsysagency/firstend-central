import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import process from 'node:process';
import {
  ALLOWED_SECURITY_EXTENSIONS,
  BLOCKED_SECURITY_EXTENSIONS,
  SENSITIVE_SECURITY_FILENAMES,
  MAX_SECURITY_FILE_SIZE_BYTES,
  MAX_TOTAL_SECURITY_SIZE_BYTES,
  SecurityItem,
  SecurityFile,
  SecurityAuditLog,
  SecurityTagSchema,
  SecurityFilePathSchema,
  SecurityFileContentSchema
} from './securityTypes.js';

// Caminho do banco de dados local
const DB_PATH = path.join(process.cwd(), 'server', 'db.json');

export interface DbSchemaSecurity {
  skills?: any[];
  security_items?: SecurityItem[];
  security_audit_logs?: SecurityAuditLog[];
  [key: string]: any;
}

// ==============================================================================
// 1. UTILITÁRIOS CRIPTOGRÁFICOS E DE SANITIZAÇÃO
// ==============================================================================

export function computeSha256(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export function sanitizeSecurityPath(rawPath: string): string {
  if (!rawPath || typeof rawPath !== 'string') {
    throw new Error('Caminho de arquivo inválido ou vazio.');
  }

  // Normalizar barras invertidas do Windows para barras normais
  let normalized = rawPath.replace(/\\/g, '/').trim();

  // Bloqueio rigoroso de caminhos absolutos
  if (normalized.startsWith('/')) {
    throw new Error('Violação de segurança: Caminho deve ser relativo (não pode iniciar com barra).');
  }

  // Bloqueio rigoroso de path traversal
  if (normalized.includes('..')) {
    throw new Error('Violação de segurança: Path traversal ("..") estritamente proibido.');
  }

  if (/^[a-zA-Z]:/.test(normalized)) {
    throw new Error('Violação de segurança: Caminhos absolutos são proibidos.');
  }

  if (normalized.includes('\0')) {
    throw new Error('Violação de segurança: Caracteres nulos detectados no caminho.');
  }

  // Validar nome base sensível
  const fileName = path.basename(normalized).toLowerCase();
  if (SENSITIVE_SECURITY_FILENAMES.includes(fileName as any)) {
    throw new Error(`Violação de segurança: Arquivos com o nome "${fileName}" são proibidos por conterem potenciais segredos.`);
  }

  // Validar extensão
  const ext = path.extname(normalized).toLowerCase();
  if (BLOCKED_SECURITY_EXTENSIONS.includes(ext as any)) {
    throw new Error(`Violação de segurança: Extensão "${ext}" é estritamente proibida por risco operacional.`);
  }

  if (!ALLOWED_SECURITY_EXTENSIONS.includes(ext as any)) {
    throw new Error(`Extensão "${ext}" não suportada. Extensões permitidas: ${ALLOWED_SECURITY_EXTENSIONS.join(', ')}`);
  }

  return normalized;
}

export function detectContentType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.md': return 'text/markdown; charset=utf-8';
    case '.json': return 'application/json; charset=utf-8';
    case '.yaml':
    case '.yml': return 'text/yaml; charset=utf-8';
    case '.ts':
    case '.tsx': return 'application/typescript; charset=utf-8';
    case '.js':
    case '.mjs':
    case '.cjs': return 'application/javascript; charset=utf-8';
    case '.py': return 'text/x-python; charset=utf-8';
    case '.sql': return 'application/sql; charset=utf-8';
    case '.sh':
    case '.ps1': return 'application/x-sh; charset=utf-8';
    case '.html': return 'text/html; charset=utf-8';
    case '.css': return 'text/css; charset=utf-8';
    default: return 'text/plain; charset=utf-8';
  }
}

// ==============================================================================
// 2. PERSISTÊNCIA ATÔMICA
// ==============================================================================

function readDb(): DbSchemaSecurity {
  try {
    if (!fs.existsSync(DB_PATH)) {
      return { security_items: [], security_audit_logs: [] };
    }
    const data = fs.readFileSync(DB_PATH, 'utf8');
    const parsed: DbSchemaSecurity = JSON.parse(data);
    if (!parsed.security_items) parsed.security_items = [];
    if (!parsed.security_audit_logs) parsed.security_audit_logs = [];
    return parsed;
  } catch (err: any) {
    console.error('Erro ao ler db.json:', err);
    return { security_items: [], security_audit_logs: [] };
  }
}

function writeDb(data: DbSchemaSecurity): void {
  try {
    const tmpPath = `${DB_PATH}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmpPath, DB_PATH);
  } catch (err: any) {
    console.error('Erro ao salvar db.json:', err);
    throw new Error('Falha ao persistir alterações na base de dados.');
  }
}

// ==============================================================================
// 3. AUDITORIA
// ==============================================================================

export function logSecurityAudit(
  securityId: string,
  action: SecurityAuditLog['action'],
  details: string,
  actor: string = 'sistema',
  metadata?: Record<string, any>
): void {
  const db = readDb();
  if (!db.security_audit_logs) db.security_audit_logs = [];

  const logEntry: SecurityAuditLog = {
    id: `sec_audit_${crypto.randomUUID()}`,
    securityId,
    actor,
    action,
    details,
    metadata,
    createdAt: new Date().toISOString()
  };

  db.security_audit_logs.push(logEntry);
  writeDb(db);
}

export function listSecurityAuditLogs(securityId: string): SecurityAuditLog[] {
  const db = readDb();
  const list = db.security_audit_logs || [];
  return list
    .filter(l => l.securityId === securityId)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

// ==============================================================================
// 4. CRUD DE ITENS DE SEGURANÇA
// ==============================================================================

export interface ListSecurityFilter {
  category?: string;
  severity?: string;
  status?: string;
  tag?: string;
  query?: string;
}

function hydrateSecurityContent(s: SecurityItem): SecurityItem {
  if (!s.content || s.content.trim() === '') {
    const secFile = (s.files || []).find(f => f.path.toLowerCase() === 'security.md' && !f.deletedAt) || s.files?.[0];
    s.content = secFile?.content || s.description || '';
  }
  return s;
}

export function listSecurityItems(filters: ListSecurityFilter = {}): SecurityItem[] {
  const db = readDb();
  let list = db.security_items || [];

  if (filters.category && filters.category !== 'todas') {
    list = list.filter(s => s.category?.toLowerCase() === filters.category!.toLowerCase());
  }

  if (filters.severity && filters.severity !== 'todas') {
    list = list.filter(s => s.severity?.toLowerCase() === filters.severity!.toLowerCase());
  }

  if (filters.status && filters.status !== 'todos') {
    list = list.filter(s => s.status?.toLowerCase() === filters.status!.toLowerCase());
  }

  if (filters.tag && filters.tag.trim()) {
    const rawTag = filters.tag.toLowerCase().replace(/^#/, '').trim();
    list = list.filter(s => s.tags?.some(t => t.toLowerCase().replace(/^#/, '') === rawTag));
  }

  if (filters.query && filters.query.trim()) {
    const q = filters.query.toLowerCase().trim();
    list = list.filter(s =>
      s.name.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      s.slug.toLowerCase().includes(q) ||
      (s.complianceStandards || []).some(c => c.toLowerCase().includes(q)) ||
      (s.tags || []).some(t => t.toLowerCase().includes(q))
    );
  }

  return list.map(hydrateSecurityContent);
}

export function getSecurityItem(idOrSlug: string): SecurityItem | null {
  if (!idOrSlug) return null;
  const db = readDb();
  const list = db.security_items || [];
  const normalized = idOrSlug.trim().toLowerCase();

  const found = list.find(s =>
    s.id === idOrSlug ||
    s.slug === idOrSlug ||
    s.slug.toLowerCase() === normalized ||
    s.id.toLowerCase() === normalized
  ) || null;

  return found ? hydrateSecurityContent(found) : null;
}

export type CreateSecurityItemPayload = Omit<Partial<SecurityItem>, 'files'> & {
  initialContent?: string;
  content?: string;
  files?: Array<Partial<SecurityFile> & { name?: string; path?: string; content?: string }>;
};

export function createSecurityItem(payload: CreateSecurityItemPayload, actor: string = 'admin'): SecurityItem {
  const db = readDb();
  if (!db.security_items) db.security_items = [];

  const id = payload.id || `sec_${crypto.randomUUID().replace(/-/g, '_').substring(0, 16)}`;
  const now = new Date().toISOString();

  const slug = (payload.slug || payload.name || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

  if (db.security_items.some(s => s.slug === slug || s.id === id)) {
    throw new Error(`Já existe um método/tecnologia de segurança com o identificador ou slug '${slug}'.`);
  }

  // Normalizar arquivos iniciais
  let normalizedFiles: SecurityFile[] = [];
  if (payload.files && Array.isArray(payload.files)) {
    for (const f of payload.files) {
      const safePath = sanitizeSecurityPath(f.path || f.name || 'arquivo.txt');
      const content = f.content || '';
      SecurityFileContentSchema.parse(content);
      const ext = path.extname(safePath).toLowerCase();
      normalizedFiles.push({
        id: f.id || `file_${crypto.randomUUID().replace(/-/g, '_').substring(0, 14)}`,
        securityId: id,
        path: safePath,
        name: f.name || path.basename(safePath),
        extension: f.extension || ext,
        contentType: f.contentType || detectContentType(safePath),
        sizeBytes: Buffer.byteLength(content, 'utf8'),
        sha256: computeSha256(content),
        content,
        version: f.version || '1.0.0',
        createdAt: f.createdAt || now,
        updatedAt: f.updatedAt || now,
        deletedAt: f.deletedAt || null
      });
    }
  }

  const documentContent = payload.content || payload.initialContent || `# ${payload.name || 'Padrão de Segurança'}\n\n## Diretrizes e Requisitos\n${payload.description || ''}\n\n## Checklist de Implementação\n- [ ] Validação no código-fonte\n- [ ] Testes de conformidade\n`;

  // Garantir arquivo SECURITY.md obrigatório
  const hasSecurityMd = normalizedFiles.some(f => f.path.toLowerCase() === 'security.md' && !f.deletedAt);

  if (!hasSecurityMd) {
    const secFile: SecurityFile = {
      id: `file_${id}_security_md`,
      securityId: id,
      path: 'SECURITY.md',
      name: 'SECURITY.md',
      extension: '.md',
      contentType: 'text/markdown; charset=utf-8',
      sizeBytes: Buffer.byteLength(documentContent, 'utf8'),
      sha256: computeSha256(documentContent),
      content: documentContent,
      version: '1.0.0',
      createdAt: now,
      updatedAt: now,
      deletedAt: null
    };
    normalizedFiles = [secFile, ...normalizedFiles];
  }

  const newItem: SecurityItem = {
    id,
    name: payload.name || 'Nova Tecnologia de Segurança',
    slug,
    description: payload.description || 'Padrão de segurança corporativo Firstsys.',
    category: payload.category || 'hardening',
    severity: payload.severity || 'alto',
    tags: Array.isArray(payload.tags) ? payload.tags.map(t => t.toLowerCase().trim()) : ['seguranca', 'firstsys'],
    status: payload.status || 'ativo',
    complianceStandards: payload.complianceStandards || ['OWASP Top 10'],
    mitigatedVulnerabilities: payload.mitigatedVulnerabilities || [],
    content: documentContent,
    files: normalizedFiles,
    createdAt: now,
    updatedAt: now
  };

  db.security_items.push(newItem);
  writeDb(db);

  logSecurityAudit(id, 'created', `Método de segurança '${newItem.name}' criado via Central`, actor, { slug, filesCount: normalizedFiles.length });
  return newItem;
}

export function updateSecurityItem(id: string, payload: Partial<SecurityItem>, actor: string = 'admin'): SecurityItem {
  const db = readDb();
  if (!db.security_items) db.security_items = [];

  const index = db.security_items.findIndex(s => s.id === id || s.slug === id);
  if (index === -1) {
    throw new Error(`Método de segurança '${id}' não encontrado.`);
  }

  const existing = db.security_items[index];
  const now = new Date().toISOString();

  let newSlug = existing.slug;
  if (payload.slug && payload.slug !== existing.slug) {
    const cleanSlug = payload.slug.toLowerCase().replace(/[^a-z0-9-]/g, '-');
    if (db.security_items.some(s => s.id !== existing.id && s.slug === cleanSlug)) {
      throw new Error(`Slug '${cleanSlug}' já está em uso por outro registro.`);
    }
    newSlug = cleanSlug;
  }

  let updatedFiles = existing.files || [];
  let updatedContent = existing.content || (existing.files?.[0]?.content) || existing.description || '';
  if (payload.content !== undefined) {
    updatedContent = payload.content;
    const secFileIdx = updatedFiles.findIndex(f => f.path.toLowerCase() === 'security.md' && !f.deletedAt);
    if (secFileIdx >= 0) {
      updatedFiles[secFileIdx] = {
        ...updatedFiles[secFileIdx],
        content: payload.content,
        sizeBytes: Buffer.byteLength(payload.content, 'utf8'),
        sha256: computeSha256(payload.content),
        updatedAt: now
      };
    }
  }

  const updated: SecurityItem = {
    ...existing,
    name: payload.name !== undefined ? payload.name : existing.name,
    slug: newSlug,
    description: payload.description !== undefined ? payload.description : existing.description,
    category: payload.category !== undefined ? payload.category : existing.category,
    severity: payload.severity !== undefined ? payload.severity : existing.severity,
    status: payload.status !== undefined ? payload.status : existing.status,
    tags: payload.tags !== undefined ? payload.tags.map(t => t.toLowerCase().trim()) : existing.tags,
    complianceStandards: payload.complianceStandards !== undefined ? payload.complianceStandards : existing.complianceStandards,
    mitigatedVulnerabilities: payload.mitigatedVulnerabilities !== undefined ? payload.mitigatedVulnerabilities : existing.mitigatedVulnerabilities,
    content: updatedContent,
    files: updatedFiles,
    updatedAt: now
  };

  db.security_items[index] = updated;
  writeDb(db);

  logSecurityAudit(existing.id, 'updated', `Método de segurança '${updated.name}' atualizado`, actor, { changedKeys: Object.keys(payload) });
  return updated;
}

export function deleteSecurityItem(id: string, actor: string = 'admin', hardDelete: boolean = false): boolean {
  const db = readDb();
  if (!db.security_items) return false;

  const index = db.security_items.findIndex(s => s.id === id || s.slug === id);
  if (index === -1) return false;

  const item = db.security_items[index];
  if (hardDelete) {
    db.security_items.splice(index, 1);
  } else {
    item.status = 'arquivado';
    item.updatedAt = new Date().toISOString();
  }
  writeDb(db);

  logSecurityAudit(item.id, 'deleted', `Método de segurança '${item.name}' ${hardDelete ? 'removido permanentemente' : 'arquivado'}`, actor);
  return true;
}

// ==============================================================================
// 5. GESTÃO DINÂMICA DE TAGS
// ==============================================================================

export function addSecurityTag(idOrSlug: string, rawTag: string, actor: string = 'admin'): SecurityItem {
  const item = getSecurityItem(idOrSlug);
  if (!item) {
    throw new Error(`Método de segurança '${idOrSlug}' não encontrado.`);
  }

  const cleanTag = rawTag.trim().toLowerCase().replace(/^#/, '');
  SecurityTagSchema.parse(cleanTag);

  const tags = item.tags || [];
  if (tags.some(t => t.toLowerCase() === cleanTag)) {
    return item; // Já existe
  }

  const updatedTags = [...tags, cleanTag];
  const updated = updateSecurityItem(item.id, { tags: updatedTags }, actor);
  logSecurityAudit(item.id, 'tag_added', `Tag '#${cleanTag}' adicionada ao item`, actor, { tag: cleanTag });
  return updated;
}

export function removeSecurityTag(idOrSlug: string, rawTag: string, actor: string = 'admin'): SecurityItem {
  const item = getSecurityItem(idOrSlug);
  if (!item) {
    throw new Error(`Método de segurança '${idOrSlug}' não encontrado.`);
  }

  const cleanTag = rawTag.trim().toLowerCase().replace(/^#/, '');
  const tags = item.tags || [];
  const updatedTags = tags.filter(t => t.toLowerCase() !== cleanTag);

  const updated = updateSecurityItem(item.id, { tags: updatedTags }, actor);
  logSecurityAudit(item.id, 'tag_removed', `Tag '#${cleanTag}' removida do item`, actor, { tag: cleanTag });
  return updated;
}

// ==============================================================================
// 6. GESTÃO DE ARQUIVOS (MÚLTIPLOS ARQUIVOS)
// ==============================================================================

export function listSecurityFiles(securityId: string, includeDeleted: boolean = false): SecurityFile[] {
  const item = getSecurityItem(securityId);
  if (!item) return [];
  return (item.files || []).filter(f => includeDeleted ? true : !f.deletedAt);
}

export function getSecurityFile(securityId: string, rawPath: string): SecurityFile | null {
  const item = getSecurityItem(securityId);
  if (!item) return null;

  const safePath = sanitizeSecurityPath(rawPath);
  return (item.files || []).find(f => f.path === safePath && !f.deletedAt) || null;
}

export function saveSecurityFile(
  securityId: string,
  rawPath: string,
  content: string,
  actor: string = 'admin'
): { securityItem: SecurityItem; file: SecurityFile } {
  const db = readDb();
  if (!db.security_items) db.security_items = [];

  const index = db.security_items.findIndex(s => s.id === securityId || s.slug === securityId);
  if (index === -1) {
    throw new Error(`Método de segurança '${securityId}' não encontrado.`);
  }

  const item = db.security_items[index];
  const safePath = sanitizeSecurityPath(rawPath);

  // Validar limites
  SecurityFileContentSchema.parse(content);
  const sizeBytes = Buffer.byteLength(content, 'utf8');

  // Calcular tamanho total
  const otherFilesSize = (item.files || [])
    .filter(f => f.path !== safePath && !f.deletedAt)
    .reduce((acc, f) => acc + f.sizeBytes, 0);

  if (otherFilesSize + sizeBytes > MAX_TOTAL_SECURITY_SIZE_BYTES) {
    throw new Error(`Limite total de armazenamento excedido (${MAX_TOTAL_SECURITY_SIZE_BYTES / 1024 / 1024} MB).`);
  }

  const now = new Date().toISOString();
  const sha256 = computeSha256(content);
  const fileName = path.basename(safePath);
  const ext = path.extname(safePath).toLowerCase();

  let targetFile = (item.files || []).find(f => f.path === safePath);
  let isNew = false;

  if (targetFile) {
    targetFile.content = content;
    targetFile.sizeBytes = sizeBytes;
    targetFile.sha256 = sha256;
    targetFile.contentType = detectContentType(safePath);
    targetFile.updatedAt = now;
    targetFile.deletedAt = null;
  } else {
    isNew = true;
    targetFile = {
      id: `secfile_${item.id.replace('sec_', '')}_${crypto.randomUUID().substring(0, 8)}`,
      securityId: item.id,
      path: safePath,
      name: fileName,
      extension: ext,
      contentType: detectContentType(safePath),
      sizeBytes,
      sha256,
      content,
      version: '1.0.0',
      createdAt: now,
      updatedAt: now,
      deletedAt: null
    };
    if (!item.files) item.files = [];
    item.files.push(targetFile);
  }

  item.updatedAt = now;
  writeDb(db);

  logSecurityAudit(
    item.id,
    isNew ? 'file_created' : 'file_updated',
    `Arquivo '${safePath}' ${isNew ? 'criado' : 'atualizado'} (${sizeBytes} bytes)`,
    actor,
    { path: safePath, sizeBytes, sha256 }
  );

  return { securityItem: item, file: targetFile };
}

export function deleteSecurityFile(
  securityId: string,
  rawPath: string,
  actor: string = 'admin',
  permanent: boolean = false
): { securityItem: SecurityItem; file: SecurityFile } {
  const db = readDb();
  if (!db.security_items) db.security_items = [];

  const index = db.security_items.findIndex(s => s.id === securityId || s.slug === securityId);
  if (index === -1) {
    throw new Error(`Método de segurança '${securityId}' não encontrado.`);
  }

  const item = db.security_items[index];
  const safePath = sanitizeSecurityPath(rawPath);

  // Proibição de exclusão do arquivo mestre SECURITY.md
  if (safePath.toLowerCase() === 'security.md') {
    throw new Error('Violação de integridade: O arquivo "SECURITY.md" é obrigatório e não pode ser excluído.');
  }

  const fileIndex = (item.files || []).findIndex(f => f.path === safePath && !f.deletedAt);
  if (fileIndex === -1) {
    throw new Error(`Arquivo '${safePath}' não encontrado.`);
  }

  const targetFile = item.files[fileIndex];
  const now = new Date().toISOString();

  if (permanent) {
    item.files.splice(fileIndex, 1);
  } else {
    targetFile.deletedAt = now;
    targetFile.updatedAt = now;
  }

  item.updatedAt = now;
  writeDb(db);

  logSecurityAudit(
    item.id,
    'file_deleted',
    `Arquivo '${safePath}' ${permanent ? 'excluído permanentemente' : 'movido para a lixeira'}`,
    actor,
    { path: safePath, permanent }
  );

  return { securityItem: item, file: targetFile };
}

export function restoreSecurityFile(
  securityId: string,
  rawPath: string,
  actor: string = 'admin'
): { securityItem: SecurityItem; file: SecurityFile } {
  const db = readDb();
  if (!db.security_items) db.security_items = [];

  const index = db.security_items.findIndex(s => s.id === securityId || s.slug === securityId);
  if (index === -1) {
    throw new Error(`Método de segurança '${securityId}' não encontrado.`);
  }

  const item = db.security_items[index];
  const safePath = sanitizeSecurityPath(rawPath);

  const targetFile = (item.files || []).find(f => f.path === safePath && f.deletedAt);
  if (!targetFile) {
    throw new Error(`Arquivo excluído '${safePath}' não encontrado para restauração.`);
  }

  const now = new Date().toISOString();
  targetFile.deletedAt = null;
  targetFile.updatedAt = now;
  item.updatedAt = now;
  writeDb(db);

  logSecurityAudit(
    item.id,
    'file_restored',
    `Arquivo '${safePath}' restaurado da lixeira`,
    actor,
    { path: safePath }
  );

  return { securityItem: item, file: targetFile };
}
