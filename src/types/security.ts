export type SecurityCategory =
  | 'hardening'
  | 'autenticacao'
  | 'criptografia'
  | 'banco_de_dados'
  | 'conformidade'
  | 'rede_api'
  | 'auditoria';

export type SecuritySeverity =
  | 'critico'
  | 'alto'
  | 'medio'
  | 'baixo'
  | 'informativo';

export type SecurityComplianceStandard =
  | 'LGPD'
  | 'OWASP Top 10'
  | 'NIST SP 800-53'
  | 'PCI-DSS v4.0'
  | 'SOC 2 Type II'
  | 'ISO 27001'
  | 'CIS Benchmarks'
  | string;

export type SecurityStatus =
  | 'ativo'
  | 'rascunho'
  | 'arquivado'
  | 'obsoleto';

export interface SecurityFile {
  id: string;
  securityId: string;
  path: string;
  name: string;
  extension: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  content: string;
  version: string;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string | null;
}

export interface SecurityAuditLog {
  id: string;
  securityId: string;
  action: string;
  details: string;
  actor: string;
  metadata?: Record<string, any>;
  createdAt: string;
}

export interface SecurityItem {
  id: string;
  slug: string;
  name: string;
  description: string;
  detailedDescription?: string;
  category: SecurityCategory;
  severity: SecuritySeverity;
  complianceStandards: SecurityComplianceStandard[];
  tags: string[];
  status: SecurityStatus;
  author: string;
  files: SecurityFile[];
  createdAt: string;
  updatedAt: string;
}
