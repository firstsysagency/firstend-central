/**
 * MÓDULO DE RETENÇÃO E CICLO DE VIDA DE DADOS (LGPD / MARCO CIVIL)
 * Central de Chaves Zatten — Checklist de Deploy 299
 */

export interface RetentionPolicy {
  httpAccessLogsDays: number;     // 180 dias (Marco Civil da Internet)
  auditLogsDays: number;          // 1825 dias (5 anos)
  revokedConnectionRetentionDays: number; // 30 dias após revogação
}

export const SYSTEM_RETENTION_POLICY: RetentionPolicy = {
  httpAccessLogsDays: 180,
  auditLogsDays: 1825,
  revokedConnectionRetentionDays: 30
};

/**
 * Determina se um registro de data ultrapassou o período legal de retenção.
 */
export function isRecordExpired(timestampIso: string, retentionDays: number): boolean {
  const recordDate = new Date(timestampIso).getTime();
  const cutoffTime = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  return recordDate < cutoffTime;
}

/**
 * Calcula a data limite de expurgo para consultas de banco de dados.
 */
export function getPurgeCutoffDate(retentionDays: number): string {
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
  return cutoff.toISOString();
}
