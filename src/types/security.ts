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
  author?: string;
  content?: string;
  files?: SecurityFile[];
  createdAt: string;
  updatedAt: string;
}

// ==============================================================================
// TIPOS DO MÓDULO DE CONTROLES DE SEGURANÇA CORPORATIVA (security_controls)
// ==============================================================================

export type SecurityControlCategory =
  | 'rede'
  | 'trafego'
  | 'api'
  | 'autenticacao'
  | 'dados'
  | 'infraestrutura'
  | 'aplicacao'
  | 'monitoramento'
  | 'incidentes'
  | 'governanca';

export type SecurityControlSeverity = 'low' | 'medium' | 'high' | 'critical';

export type SecurityControlStatus =
  | 'planned'
  | 'in_progress'
  | 'implemented'
  | 'verified'
  | 'not_applicable'
  | 'exception';

export interface SecurityControl {
  id: string;
  control_code: string;
  name: string;
  category: SecurityControlCategory;
  description: string;
  rationale: string;
  implementation: string;
  validation_method: string;
  evidence: string;
  severity: SecurityControlSeverity;
  status: SecurityControlStatus;
  owner: string;
  last_verified_at: string | null;
  next_review_at: string | null;
  created_at: string;
  updated_at: string;
  revision: number;
  is_archived: boolean;
  archived_at: string | null;
}

export interface SecurityControlEvidence {
  id: string;
  control_id: string;
  control_code: string;
  title: string;
  description: string;
  evidence_type: 'log' | 'metric' | 'config' | 'report' | 'screenshot' | 'code' | 'other';
  evidence_url?: string;
  evidence_data?: string;
  hash: string;
  created_at: string;
  created_by: string;
}

export interface SecurityControlException {
  id: string;
  control_id: string;
  control_code: string;
  reason: string;
  approved_by: string;
  risk_accepted: boolean;
  expires_at: string;
  status: 'active' | 'resolved' | 'expired' | 'revoked';
  created_at: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
  resolution_notes?: string | null;
}

export interface SecurityAuditEvent {
  id: string;
  event_type: string;
  entity_type: string;
  entity_id: string;
  control_code: string;
  actor: string;
  ip_origin: string;
  diff?: Record<string, { old: any; new: any }>;
  created_at: string;
}

export interface SecurityPostureSummary {
  total_controls: number;
  active_controls: number;
  archived_controls: number;
  by_status: Record<SecurityControlStatus, number>;
  by_severity: Record<SecurityControlSeverity, number>;
  by_category: Record<SecurityControlCategory, number>;
  compliance_rate_percent: number;
  overdue_reviews_count: number;
  active_exceptions_count: number;
  total_evidences_count: number;
  generated_at: string;
}

