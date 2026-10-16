export interface SkillFile {
  id: string;
  skillId: string;
  path: string;
  name: string;
  extension: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  content: string;
  origin: 'local' | 'git';
  isExecutable: boolean;
  requiresReview: boolean;
  version: string;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string | null;
}

export interface SkillInstallation {
  id: string;
  skillId: string;
  contextType: 'agent' | 'connection' | 'project' | 'mcp' | 'environment';
  contextId: string;
  contextName: string;
  pinnedVersion: string;
  status: 'active' | 'inactive';
  config: Record<string, any>;
  grantedPermissions: string[];
  installedAt: string;
  installedBy: string;
}

export interface SkillVersion {
  id: string;
  skillId: string;
  version: string;
  changelog: string;
  snapshotHash: string;
  filesSnapshot: {
    path: string;
    sha256: string;
    sizeBytes: number;
    name: string;
  }[];
  createdAt: string;
  createdBy: string;
}

export type SkillOrigin = 'propria' | 'importada' | 'clonada' | 'curada';
export type SkillStatus = 'rascunho' | 'ativa' | 'arquivada' | 'descontinuada' | 'active' | 'inactive';
export type SkillRiskLevel = 'baixo' | 'medio' | 'alto';

export interface SkillItem {
  id: string;
  slug: string;
  name: string;
  description: string;
  detailedDescription?: string;
  category: string;
  tags: string[];
  author: string;
  origin: SkillOrigin;
  status: SkillStatus;
  installed: boolean; // Retrocompatibilidade Zatten
  version: string;
  createdAt: string;
  updatedAt: string;
  license: string;
  repositoryUrl?: string | null;
  repositoryOwner?: string | null;
  repositoryBranch?: string | null;
  repositoryCommitSha?: string | null;
  lastSyncAt?: string | null;
  securityWarnings: string[];
  riskLevel: SkillRiskLevel;
  compatibility: string[];
  dependencies: string[];
  permissions: string[];
  files: SkillFile[];
  installations?: SkillInstallation[];
}

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

export interface SkillAuditLog {
  id: string;
  skillId: string;
  actor: string;
  action: string;
  details: string;
  metadata?: Record<string, any>;
  createdAt: string;
}
