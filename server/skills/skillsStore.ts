import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
  ALLOWED_TEXT_EXTENSIONS,
  BLOCKED_OR_SUSPICIOUS_EXTENSIONS,
  SENSITIVE_FILE_NAMES,
  MAX_FILE_SIZE_BYTES,
  MAX_TOTAL_SKILL_SIZE_BYTES,
  Skill,
  SkillFile,
  SkillVersion,
  SkillInstallation,
  SkillAuditLog,
  SkillFilePathSchema,
  SkillFileContentSchema
} from './skillTypes.js';

// Caminho do banco de dados local
const DB_PATH = path.join(process.cwd(), 'server', 'db.json');

// ==============================================================================
// 1. UTILITÁRIOS CRIPTOGRÁFICOS E DE SANITIZAÇÃO DE PATH TRAVERSAL
// ==============================================================================

export function computeSha256(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export function sanitizeRelativePath(rawPath: string): string {
  if (!rawPath || typeof rawPath !== 'string') {
    throw new Error('Caminho de arquivo inválido ou vazio.');
  }

  // Normalizar barras invertidas do Windows para barras normais
  let normalized = rawPath.replace(/\\/g, '/').trim();

  // Bloqueio rigoroso de caminhos absolutos (iniciando com barra ou unidade)
  if (normalized.startsWith('/')) {
    throw new Error('Violação de segurança: Caminho deve ser relativo ao diretório da skill (não pode iniciar com barra).');
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

  // Validar nome base
  const fileName = path.basename(normalized).toLowerCase();
  if (SENSITIVE_FILE_NAMES.includes(fileName as any)) {
    throw new Error(`Violação de segurança: Arquivos com o nome "${fileName}" são proibidos por conterem potenciais segredos.`);
  }

  // Validar extensão
  const dotIndex = normalized.lastIndexOf('.');
  if (dotIndex === -1) {
    throw new Error('Arquivo deve possuir uma extensão permitida (ex: .md, .json, .ts).');
  }

  const ext = normalized.substring(dotIndex).toLowerCase();
  if (BLOCKED_OR_SUSPICIOUS_EXTENSIONS.includes(ext as any)) {
    throw new Error(`Extensão de arquivo bloqueada por motivos de segurança: ${ext}`);
  }

  if (!ALLOWED_TEXT_EXTENSIONS.includes(ext as any)) {
    throw new Error(`Extensão "${ext}" não permitida. Extensões válidas: ${ALLOWED_TEXT_EXTENSIONS.join(', ')}`);
  }

  // Validação pelo schema Zod
  SkillFilePathSchema.parse(normalized);

  return normalized;
}

export function isExecutablePath(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ['.ts', '.tsx', '.js', '.mjs', '.cjs', '.py', '.sh', '.ps1'].includes(ext);
}

export function detectContentType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.md': return 'text/markdown';
    case '.json': return 'application/json';
    case '.yaml':
    case '.yml': return 'text/yaml';
    case '.ts':
    case '.tsx': return 'text/typescript';
    case '.js':
    case '.mjs':
    case '.cjs': return 'application/javascript';
    case '.py': return 'text/x-python';
    case '.sh': return 'application/x-sh';
    case '.ps1': return 'text/plain';
    case '.html': return 'text/html';
    case '.css': return 'text/css';
    case '.sql': return 'text/x-sql';
    default: return 'text/plain';
  }
}

// ==============================================================================
// 2. PERSISTÊNCIA E LEITURA SEGURA DO DB.JSON
// ==============================================================================

interface DbSchema {
  users?: any[];
  connections?: any[];
  mcpPermissions?: any[];
  skills?: Skill[];
  skill_versions?: SkillVersion[];
  skill_installations?: SkillInstallation[];
  skill_audit_logs?: SkillAuditLog[];
  [key: string]: any;
}

function readDb(): DbSchema {
  try {
    if (!fs.existsSync(DB_PATH)) {
      return { skills: [], skill_versions: [], skill_installations: [], skill_audit_logs: [] };
    }
    const data = fs.readFileSync(DB_PATH, 'utf8');
    const parsed: DbSchema = JSON.parse(data);
    
    // Auto-migração em tempo de leitura de registros legados da VPS
    let mutated = false;
    if (parsed.skills && Array.isArray(parsed.skills)) {
      for (const s of parsed.skills) {
        if (s.slug === 'descoberta-e-curadoria-de-skills' || s.id === 'skill_curada_find_skills_vercel') {
          s.slug = 'find-skills-vercel';
          s.id = 'skill_find_skills_vercel';
          s.name = 'Find Skills — Vercel';
          mutated = true;
        }
      }
    }
    if (mutated) {
      try {
        fs.writeFileSync(DB_PATH, JSON.stringify(parsed, null, 2), 'utf8');
      } catch (err) {
        console.warn('Aviso: Não foi possível salvar migração de slug no db.json:', err);
      }
    }

    return parsed;
  } catch (err: any) {
    console.error('Erro ao ler db.json:', err);
    return { skills: [], skill_versions: [], skill_installations: [], skill_audit_logs: [] };
  }
}

function writeDb(data: DbSchema): void {
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
// 3. AUDITORIA INTERNA
// ==============================================================================

export function logSkillAudit(
  skillId: string,
  action: SkillAuditLog['action'],
  details: string,
  actor: string = 'sistema',
  metadata?: Record<string, any>
): void {
  const db = readDb();
  if (!db.skill_audit_logs) db.skill_audit_logs = [];

  const logEntry: SkillAuditLog = {
    id: `audit_${crypto.randomUUID()}`,
    skillId,
    actor,
    action,
    details,
    metadata,
    createdAt: new Date().toISOString()
  };

  db.skill_audit_logs.push(logEntry);
  writeDb(db);
}

// ==============================================================================
// 4. OPERAÇÕES CRUD DE SKILLS
// ==============================================================================

export interface ListSkillsFilter {
  category?: string;
  origin?: string;
  status?: string;
  riskLevel?: string;
  query?: string;
  installedOnly?: boolean;
}

export function listSkills(filters: ListSkillsFilter = {}): Skill[] {
  const db = readDb();
  let list = db.skills || [];

  if (filters.category && filters.category !== 'todas') {
    list = list.filter(s => s.category?.toLowerCase() === filters.category!.toLowerCase());
  }

  if (filters.origin && filters.origin !== 'todos') {
    list = list.filter(s => s.origin?.toLowerCase() === filters.origin!.toLowerCase());
  }

  if (filters.status && filters.status !== 'todos') {
    list = list.filter(s => s.status?.toLowerCase() === filters.status!.toLowerCase());
  }

  if (filters.riskLevel && filters.riskLevel !== 'todos') {
    list = list.filter(s => s.riskLevel?.toLowerCase() === filters.riskLevel!.toLowerCase());
  }

  if (filters.installedOnly) {
    list = list.filter(s => s.installed === true);
  }

  if (filters.query && filters.query.trim()) {
    const q = filters.query.toLowerCase().trim();
    list = list.filter(s =>
      s.name.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      s.slug.toLowerCase().includes(q) ||
      s.tags.some(t => t.toLowerCase().includes(q))
    );
  }

  return list;
}

export function getSkill(idOrSlug: string): Skill | null {
  if (!idOrSlug) return null;
  const db = readDb();
  const list = db.skills || [];
  const normalized = idOrSlug.trim().toLowerCase();

  return list.find(s => {
    if (s.id === idOrSlug || s.slug === idOrSlug) return true;
    if (s.slug?.toLowerCase() === normalized || s.id?.toLowerCase() === normalized) return true;
    // Alias bidirecional para find-skills-vercel e descoberta-e-curadoria-de-skills
    if (
      (normalized === 'find-skills-vercel' || normalized === 'skill_find_skills_vercel') &&
      (s.slug === 'descoberta-e-curadoria-de-skills' || s.id === 'skill_curada_find_skills_vercel')
    ) {
      return true;
    }
    if (
      (normalized === 'descoberta-e-curadoria-de-skills' || normalized === 'skill_curada_find_skills_vercel') &&
      (s.slug === 'find-skills-vercel' || s.id === 'skill_find_skills_vercel')
    ) {
      return true;
    }
    return false;
  }) || null;
}

export function createSkill(payload: Partial<Skill>, actor: string = 'admin'): Skill {
  const db = readDb();
  if (!db.skills) db.skills = [];

  const id = payload.id || `skill_${crypto.randomUUID().replace(/-/g, '_').substring(0, 16)}`;
  const slug = (payload.slug || payload.name?.toLowerCase().replace(/[^a-z0-9]/g, '-') || `skill-${Date.now()}`)
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');

  // Validar se slug ou id já existem
  if (db.skills.some(s => s.id === id || s.slug === slug)) {
    throw new Error(`Já existe uma skill cadastrada com o slug "${slug}" ou ID "${id}".`);
  }

  const now = new Date().toISOString();
  const version = payload.version || '1.0.0';

  // Processar arquivos iniciais
  const initialFiles: SkillFile[] = [];
  if (payload.files && Array.isArray(payload.files)) {
    for (const f of payload.files) {
      const relPath = sanitizeRelativePath(f.path || f.name);
      const content = f.content || '';
      SkillFileContentSchema.parse(content);
      const sizeBytes = Buffer.byteLength(content, 'utf8');
      const sha256 = computeSha256(content);
      const isExec = isExecutablePath(relPath);

      initialFiles.push({
        id: `file_${crypto.randomUUID().replace(/-/g, '_').substring(0, 14)}`,
        skillId: id,
        path: relPath,
        name: path.basename(relPath),
        extension: path.extname(relPath),
        contentType: detectContentType(relPath),
        sizeBytes,
        sha256,
        content,
        origin: f.origin || 'local',
        isExecutable: isExec,
        requiresReview: isExec,
        version,
        createdAt: now,
        updatedAt: now,
        deletedAt: null
      });
    }
  }

  // Se não houver SKILL.md, cria um arquivo padrão estruturado
  if (!initialFiles.some(f => f.path.toLowerCase() === 'skill.md')) {
    const defaultSkillMd = `---
name: ${slug}
description: ${payload.description || payload.name || 'Nova Skill Firstsys'}
version: ${version}
category: ${payload.category || 'geral'}
---

# ${payload.name || 'Nova Skill Firstsys'}

## Visão Geral
${payload.description || 'Instruções e diretrizes operacionais de comportamento desta skill.'}

## Diretrizes de Execução
1. Respeite as regras e contexto definidos para a tarefa.
2. Não realize suposições sem conferir os dados necessários.
`;
    const sha = computeSha256(defaultSkillMd);
    initialFiles.unshift({
      id: `file_${crypto.randomUUID().replace(/-/g, '_').substring(0, 14)}`,
      skillId: id,
      path: 'SKILL.md',
      name: 'SKILL.md',
      extension: '.md',
      contentType: 'text/markdown',
      sizeBytes: Buffer.byteLength(defaultSkillMd, 'utf8'),
      sha256: sha,
      content: defaultSkillMd,
      origin: 'local',
      isExecutable: false,
      requiresReview: false,
      version,
      createdAt: now,
      updatedAt: now,
      deletedAt: null
    });
  }

  const newSkill: Skill = {
    id,
    slug,
    name: payload.name || 'Nova Skill',
    description: payload.description || 'Descrição detalhada da skill',
    detailedDescription: payload.detailedDescription || '',
    category: payload.category || 'geral',
    tags: payload.tags || [],
    author: payload.author || 'Firstsys AI',
    origin: payload.origin || 'propria',
    status: payload.status || 'ativa',
    installed: payload.installed ?? false,
    version,
    createdAt: now,
    updatedAt: now,
    license: payload.license || 'Proprietária Firstsys',
    repositoryUrl: payload.repositoryUrl || null,
    repositoryOwner: payload.repositoryOwner || null,
    repositoryBranch: payload.repositoryBranch || null,
    repositoryCommitSha: payload.repositoryCommitSha || null,
    lastSyncAt: payload.lastSyncAt || null,
    securityWarnings: payload.securityWarnings || [],
    riskLevel: payload.riskLevel || 'baixo',
    compatibility: payload.compatibility || [],
    dependencies: payload.dependencies || [],
    permissions: payload.permissions || [],
    files: initialFiles
  };

  db.skills.push(newSkill);
  writeDb(db);

  // Criar snapshot inicial de versão
  createVersionSnapshot(newSkill.id, 'Versão inicial da skill criada', actor, version);
  logSkillAudit(newSkill.id, 'skill.created', `Skill "${newSkill.name}" criada com sucesso`, actor);

  return newSkill;
}

export function updateSkill(id: string, patch: Partial<Skill>, actor: string = 'admin'): Skill {
  const db = readDb();
  if (!db.skills) db.skills = [];

  const index = db.skills.findIndex(s => s.id === id);
  if (index === -1) {
    throw new Error(`Skill com ID "${id}" não encontrada.`);
  }

  const current = db.skills[index];
  const now = new Date().toISOString();

  const updated: Skill = {
    ...current,
    ...patch,
    id: current.id, // ID é imutável
    files: current.files, // Arquivos são manipulados por métodos específicos
    updatedAt: now
  };

  db.skills[index] = updated;
  writeDb(db);

  logSkillAudit(id, 'skill.updated', `Metadados da skill "${updated.name}" atualizados`, actor);
  return updated;
}

export function deleteSkill(id: string, actor: string = 'admin', hardDelete: boolean = false): void {
  const db = readDb();
  if (!db.skills) return;

  const skill = db.skills.find(s => s.id === id);
  if (!skill) {
    throw new Error(`Skill com ID "${id}" não encontrada.`);
  }

  if (hardDelete) {
    db.skills = db.skills.filter(s => s.id !== id);
    if (db.skill_installations) {
      db.skill_installations = db.skill_installations.filter(i => i.skillId !== id);
    }
    writeDb(db);
    logSkillAudit(id, 'skill.deleted', `Skill "${skill.name}" excluída permanentemente`, actor);
  } else {
    // Soft delete: status arquivada
    skill.status = 'arquivada';
    skill.updatedAt = new Date().toISOString();
    writeDb(db);
    logSkillAudit(id, 'skill.deleted', `Skill "${skill.name}" marcada como arquivada`, actor);
  }
}

export function toggleInstallSkill(id: string, installed?: boolean, actor: string = 'admin'): { skill: Skill; installed: boolean } {
  const db = readDb();
  if (!db.skills) db.skills = [];

  const skill = db.skills.find(s => s.id === id);
  if (!skill) {
    throw new Error(`Skill com ID "${id}" não encontrada.`);
  }

  const newStatus = typeof installed === 'boolean' ? installed : !skill.installed;
  skill.installed = newStatus;
  skill.status = newStatus ? 'ativa' : 'rascunho';
  skill.updatedAt = new Date().toISOString();

  writeDb(db);

  const action = newStatus ? 'skill.installed' : 'skill.uninstalled';
  logSkillAudit(id, action, `Status de instalação alterado para: ${newStatus ? 'Instalada/Ativa' : 'Desinstalada'}`, actor);

  return { skill, installed: newStatus };
}

export function addSkillTag(id: string, rawTag: string, actor: string = 'admin'): Skill {
  const db = readDb();
  if (!db.skills) db.skills = [];

  const skill = db.skills.find(s => s.id === id || s.slug === id);
  if (!skill) {
    throw new Error(`Skill com identificador "${id}" não encontrada.`);
  }

  const cleanTag = rawTag.toLowerCase().trim().replace(/^#/, '').replace(/[^a-z0-9_-]/g, '');
  if (!cleanTag) {
    throw new Error('Nome da tag inválido.');
  }

  if (!skill.tags.includes(cleanTag)) {
    skill.tags.push(cleanTag);
    skill.updatedAt = new Date().toISOString();
    writeDb(db);
    logSkillAudit(skill.id, 'skill.tag_added', `Tag "#${cleanTag}" adicionada à skill`, actor);
  }

  return skill;
}

export function removeSkillTag(id: string, rawTag: string, actor: string = 'admin'): Skill {
  const db = readDb();
  if (!db.skills) db.skills = [];

  const skill = db.skills.find(s => s.id === id || s.slug === id);
  if (!skill) {
    throw new Error(`Skill com identificador "${id}" não encontrada.`);
  }

  const cleanTag = rawTag.toLowerCase().trim().replace(/^#/, '');
  skill.tags = skill.tags.filter(t => t !== cleanTag);
  skill.updatedAt = new Date().toISOString();
  writeDb(db);
  logSkillAudit(skill.id, 'skill.tag_removed', `Tag "#${cleanTag}" removida da skill`, actor);

  return skill;
}

// ==============================================================================
// 5. GERENCIAMENTO DE ARQUIVOS (MULTI-ARQUIVOS EM ÁRVORE)
// ==============================================================================

export function listSkillFiles(skillId: string, includeDeleted: boolean = false): SkillFile[] {
  const skill = getSkill(skillId);
  if (!skill) throw new Error(`Skill com ID "${skillId}" não encontrada.`);

  let files = skill.files || [];
  if (!includeDeleted) {
    files = files.filter(f => !f.deletedAt);
  }
  return files;
}

export function getSkillFile(skillId: string, rawRelativePath: string): SkillFile | null {
  const safePath = sanitizeRelativePath(rawRelativePath);
  const files = listSkillFiles(skillId, true);
  return files.find(f => f.path.toLowerCase() === safePath.toLowerCase()) || null;
}

export function saveSkillFile(
  skillId: string,
  rawRelativePath: string,
  content: string,
  actor: string = 'admin',
  origin: 'local' | 'git' = 'local'
): { skill: Skill; file: SkillFile } {
  const safePath = sanitizeRelativePath(rawRelativePath);
  SkillFileContentSchema.parse(content);

  const db = readDb();
  if (!db.skills) db.skills = [];

  const skill = db.skills.find(s => s.id === skillId);
  if (!skill) throw new Error(`Skill com ID "${skillId}" não encontrada.`);

  if (!skill.files) skill.files = [];

  const sizeBytes = Buffer.byteLength(content, 'utf8');
  const sha256 = computeSha256(content);
  const isExec = isExecutablePath(safePath);
  const now = new Date().toISOString();

  // Verificar limite total da skill
  const otherFilesSize = skill.files
    .filter(f => f.path.toLowerCase() !== safePath.toLowerCase() && !f.deletedAt)
    .reduce((acc, f) => acc + (f.sizeBytes || 0), 0);

  if (otherFilesSize + sizeBytes > MAX_TOTAL_SKILL_SIZE_BYTES) {
    throw new Error(`Tamanho total dos arquivos da skill excede o limite máximo de ${MAX_TOTAL_SKILL_SIZE_BYTES / (1024 * 1024)} MB.`);
  }

  const existingIndex = skill.files.findIndex(f => f.path.toLowerCase() === safePath.toLowerCase());
  let targetFile: SkillFile;

  if (existingIndex >= 0) {
    const existing = skill.files[existingIndex];
    targetFile = {
      ...existing,
      content,
      sizeBytes,
      sha256,
      extension: path.extname(safePath),
      contentType: detectContentType(safePath),
      isExecutable: isExec,
      requiresReview: isExec ? true : existing.requiresReview,
      updatedAt: now,
      deletedAt: null // Se estava deletado, restaura
    };
    skill.files[existingIndex] = targetFile;
    logSkillAudit(skillId, 'file.updated', `Arquivo "${safePath}" atualizado (SHA-256: ${sha256.substring(0, 8)}...)`, actor);
  } else {
    targetFile = {
      id: `file_${crypto.randomUUID().replace(/-/g, '_').substring(0, 14)}`,
      skillId,
      path: safePath,
      name: path.basename(safePath),
      extension: path.extname(safePath),
      contentType: detectContentType(safePath),
      sizeBytes,
      sha256,
      content,
      origin,
      isExecutable: isExec,
      requiresReview: isExec,
      version: skill.version,
      createdAt: now,
      updatedAt: now,
      deletedAt: null
    };
    skill.files.push(targetFile);
    logSkillAudit(skillId, 'file.created', `Novo arquivo "${safePath}" adicionado à skill`, actor);
  }

  skill.updatedAt = now;
  writeDb(db);

  return { skill, file: targetFile };
}

export function deleteSkillFile(
  skillId: string,
  rawRelativePath: string,
  actor: string = 'admin',
  permanent: boolean = false
): { skill: Skill } {
  const safePath = sanitizeRelativePath(rawRelativePath);
  if (safePath.toLowerCase() === 'skill.md') {
    throw new Error('O arquivo raiz "SKILL.md" é obrigatório e não pode ser excluído.');
  }

  const db = readDb();
  if (!db.skills) db.skills = [];

  const skill = db.skills.find(s => s.id === skillId);
  if (!skill) throw new Error(`Skill com ID "${skillId}" não encontrada.`);

  if (!skill.files) return { skill };

  const file = skill.files.find(f => f.path.toLowerCase() === safePath.toLowerCase());
  if (!file) throw new Error(`Arquivo "${safePath}" não encontrado na skill.`);

  const now = new Date().toISOString();

  if (permanent) {
    skill.files = skill.files.filter(f => f.path.toLowerCase() !== safePath.toLowerCase());
    logSkillAudit(skillId, 'file.deleted', `Arquivo "${safePath}" removido permanentemente`, actor);
  } else {
    file.deletedAt = now;
    file.updatedAt = now;
    logSkillAudit(skillId, 'file.deleted', `Arquivo "${safePath}" movido para lixeira (soft delete)`, actor);
  }

  skill.updatedAt = now;
  writeDb(db);

  return { skill };
}

export function restoreSkillFile(
  skillId: string,
  rawRelativePath: string,
  actor: string = 'admin'
): { skill: Skill; file: SkillFile } {
  const safePath = sanitizeRelativePath(rawRelativePath);
  const db = readDb();
  if (!db.skills) db.skills = [];

  const skill = db.skills.find(s => s.id === skillId);
  if (!skill) throw new Error(`Skill com ID "${skillId}" não encontrada.`);

  const file = skill.files?.find(f => f.path.toLowerCase() === safePath.toLowerCase());
  if (!file) throw new Error(`Arquivo "${safePath}" não encontrado na skill.`);

  file.deletedAt = null;
  file.updatedAt = new Date().toISOString();
  skill.updatedAt = new Date().toISOString();

  writeDb(db);
  logSkillAudit(skillId, 'file.restored', `Arquivo "${safePath}" restaurado com sucesso`, actor);

  return { skill, file };
}

// ==============================================================================
// 6. VERSIONAMENTO SEMÂNTICO E HISTÓRICO DE SNAPSHOTS
// ==============================================================================

export function createVersionSnapshot(
  skillId: string,
  changelog: string,
  createdBy: string = 'admin',
  explicitVersion?: string
): SkillVersion {
  const db = readDb();
  if (!db.skill_versions) db.skill_versions = [];

  const skill = db.skills?.find(s => s.id === skillId);
  if (!skill) throw new Error(`Skill com ID "${skillId}" não encontrada.`);

  const currentFiles = (skill.files || []).filter(f => !f.deletedAt);
  const filesSnapshot = currentFiles.map(f => ({
    path: f.path,
    sha256: f.sha256,
    sizeBytes: f.sizeBytes,
    name: f.name
  }));

  // Hash geral do snapshot combinando os hashes dos arquivos ordenados
  const sortedHashes = filesSnapshot.map(f => `${f.path}:${f.sha256}`).sort().join('|');
  const snapshotHash = computeSha256(sortedHashes);

  let versionToUse = explicitVersion || skill.version;
  if (!explicitVersion) {
    // Se não informada versão explicitamente, incrementa patch se já existir
    const existingVer = db.skill_versions.some(v => v.skillId === skillId && v.version === versionToUse);
    if (existingVer) {
      const parts = versionToUse.split('.').map(Number);
      if (parts.length === 3 && !parts.some(isNaN)) {
        parts[2]++;
        versionToUse = parts.join('.');
        skill.version = versionToUse;
      }
    }
  }

  const newVersion: SkillVersion = {
    id: `ver_${crypto.randomUUID().replace(/-/g, '_').substring(0, 14)}`,
    skillId,
    version: versionToUse,
    changelog: changelog || 'Atualização e snapshot de integridade da skill',
    snapshotHash,
    filesSnapshot,
    createdAt: new Date().toISOString(),
    createdBy
  };

  db.skill_versions.push(newVersion);
  skill.version = versionToUse;
  skill.updatedAt = new Date().toISOString();

  writeDb(db);
  logSkillAudit(skillId, 'version.created', `Versão ${versionToUse} registrada (Snapshot: ${snapshotHash.substring(0, 8)}...)`, createdBy);

  return newVersion;
}

export function listSkillVersions(skillId: string): SkillVersion[] {
  const db = readDb();
  return (db.skill_versions || [])
    .filter(v => v.skillId === skillId)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

export function getSkillVersion(skillId: string, versionNumber: string): SkillVersion | null {
  const db = readDb();
  return (db.skill_versions || []).find(v => v.skillId === skillId && v.version === versionNumber) || null;
}

export function compareSkillVersions(
  skillId: string,
  versionA: string,
  versionB: string
): {
  versionA: string;
  versionB: string;
  addedFiles: string[];
  removedFiles: string[];
  modifiedFiles: string[];
  unchangedFiles: string[];
} {
  const vA = getSkillVersion(skillId, versionA);
  const vB = getSkillVersion(skillId, versionB);

  if (!vA || !vB) {
    throw new Error('Uma ou ambas as versões especificadas não foram encontradas.');
  }

  const mapA = new Map(vA.filesSnapshot.map(f => [f.path, f.sha256]));
  const mapB = new Map(vB.filesSnapshot.map(f => [f.path, f.sha256]));

  const addedFiles: string[] = [];
  const removedFiles: string[] = [];
  const modifiedFiles: string[] = [];
  const unchangedFiles: string[] = [];

  for (const [pathB, hashB] of mapB.entries()) {
    if (!mapA.has(pathB)) {
      addedFiles.push(pathB);
    } else if (mapA.get(pathB) === hashB) {
      unchangedFiles.push(pathB);
    } else {
      modifiedFiles.push(pathB);
    }
  }

  for (const pathA of mapA.keys()) {
    if (!mapB.has(pathA)) {
      removedFiles.push(pathA);
    }
  }

  return {
    versionA,
    versionB,
    addedFiles,
    removedFiles,
    modifiedFiles,
    unchangedFiles
  };
}

// ==============================================================================
// 7. INSTALAÇÃO GRANULAR POR CONTEXTO (AGENTES, CONEXÕES, PROJETOS, MCP)
// ==============================================================================

export function listSkillInstallations(skillId: string): SkillInstallation[] {
  const db = readDb();
  return (db.skill_installations || []).filter(i => i.skillId === skillId);
}

export function createSkillInstallation(
  skillId: string,
  payload: {
    contextType: SkillInstallation['contextType'];
    contextId: string;
    contextName: string;
    pinnedVersion?: string;
    config?: Record<string, any>;
    grantedPermissions?: string[];
  },
  actor: string = 'admin'
): SkillInstallation {
  const db = readDb();
  if (!db.skill_installations) db.skill_installations = [];

  const skill = db.skills?.find(s => s.id === skillId);
  if (!skill) throw new Error(`Skill com ID "${skillId}" não encontrada.`);

  // Evitar duplicidade de instalação no mesmo contexto
  const existing = db.skill_installations.find(
    i => i.skillId === skillId && i.contextType === payload.contextType && i.contextId === payload.contextId
  );

  const pinnedVersion = payload.pinnedVersion || skill.version;
  const now = new Date().toISOString();

  if (existing) {
    existing.pinnedVersion = pinnedVersion;
    existing.status = 'active';
    existing.contextName = payload.contextName || existing.contextName;
    existing.config = payload.config || existing.config;
    existing.grantedPermissions = payload.grantedPermissions || existing.grantedPermissions;
    writeDb(db);
    logSkillAudit(skillId, 'skill.installed', `Instalação no contexto [${payload.contextType}:${payload.contextId}] atualizada para versão ${pinnedVersion}`, actor);
    return existing;
  }

  const newInstall: SkillInstallation = {
    id: `inst_${crypto.randomUUID().replace(/-/g, '_').substring(0, 14)}`,
    skillId,
    contextType: payload.contextType,
    contextId: payload.contextId,
    contextName: payload.contextName,
    pinnedVersion,
    status: 'active',
    config: payload.config || {},
    grantedPermissions: payload.grantedPermissions || [],
    installedAt: now,
    installedBy: actor
  };

  db.skill_installations.push(newInstall);
  writeDb(db);

  logSkillAudit(skillId, 'skill.installed', `Skill vinculada com sucesso ao contexto [${payload.contextType}: ${payload.contextName}] na versão ${pinnedVersion}`, actor);
  return newInstall;
}

export function deleteSkillInstallation(skillId: string, installationId: string, actor: string = 'admin'): void {
  const db = readDb();
  if (!db.skill_installations) return;

  const target = db.skill_installations.find(i => i.id === installationId && i.skillId === skillId);
  if (!target) {
    throw new Error(`Instalação com ID "${installationId}" não encontrada.`);
  }

  db.skill_installations = db.skill_installations.filter(i => i.id !== installationId);
  writeDb(db);

  logSkillAudit(skillId, 'skill.uninstalled', `Desinstalada do contexto [${target.contextType}: ${target.contextName}]`, actor);
}

// ==============================================================================
// 8. LOGS DE AUDITORIA
// ==============================================================================

export function listSkillAuditLogs(skillId: string): SkillAuditLog[] {
  const db = readDb();
  const skill = getSkill(skillId);
  const targetIds = new Set<string>([skillId]);

  if (skill) {
    targetIds.add(skill.id);
    targetIds.add(skill.slug);
  }

  // Aliases conhecidos para compatibilidade retroativa absoluta
  if (skillId === 'find-skills-vercel' || skill?.slug === 'find-skills-vercel') {
    targetIds.add('skill_curada_find_skills_vercel');
    targetIds.add('descoberta-e-curadoria-de-skills');
    targetIds.add('skill_find_skills_vercel');
    targetIds.add('find-skills-vercel');
  }

  return (db.skill_audit_logs || [])
    .filter(l => targetIds.has(l.skillId))
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

