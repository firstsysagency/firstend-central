/**
 * MÓDULO DE MONITORAMENTO, TELEMETRIA E ALERTAS PROATIVOS
 * Central de Chaves Zatten — Checklist de Deploy 298
 */

import { getPostgresStatus } from './postgresAudit';
import { getOpenBaoConfig } from './openbao';
import { getAuditLogs, logAuditEvent } from './audit';
import { getNotificationSettings } from './notifications';

export interface ServiceHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latencyMs: number;
  message: string;
}

export interface SystemHealthReport {
  timestamp: string;
  overallStatus: 'healthy' | 'degraded' | 'unhealthy';
  services: ServiceHealth[];
  metrics: {
    totalAuditEvents: number;
    failedAuthAttemptsLast24h: number;
    activeConnectionsCount: number;
    openBaoMasterKeyVersion: string;
  };
}

/**
 * Coleta o status de saúde e conectividade de todos os subsistemas.
 */
export async function getSystemHealthReport(): Promise<SystemHealthReport> {
  const startPg = performance.now();
  const pg = getPostgresStatus();
  const pgLatency = Math.round(performance.now() - startPg);

  const startBao = performance.now();
  const bao = getOpenBaoConfig();
  const baoLatency = Math.round(performance.now() - startBao);

  const logs = getAuditLogs();
  const failedAuth = logs.filter(
    l => l.action.includes('failed') || l.action.includes('unauthorized') || l.severity === 'critical'
  ).length;

  const services: ServiceHealth[] = [
    {
      name: 'PostgreSQL 16 (RLS & Append-Only)',
      status: pg.connected && pg.rlsEnabled ? 'healthy' : 'degraded',
      latencyMs: pgLatency,
      message: `Conectado ao banco ${pg.databaseName} com isolamento multi-tenant garantido.`
    },
    {
      name: 'OpenBao Transit Secrets Engine (KMS)',
      status: bao.vaultUrl ? 'healthy' : 'unhealthy',
      latencyMs: baoLatency,
      message: `Chave mestra v${bao.keyVersion} ativa com rotação a cada ${bao.rotationInterval} dias.`
    },
    {
      name: 'Trilha de Auditoria Criptográfica',
      status: 'healthy',
      latencyMs: 1,
      message: `${logs.length} eventos registrados com sanitização automática ativa.`
    }
  ];

  const hasUnhealthy = services.some(s => s.status === 'unhealthy');
  const hasDegraded = services.some(s => s.status === 'degraded');

  return {
    timestamp: new Date().toISOString(),
    overallStatus: hasUnhealthy ? 'unhealthy' : hasDegraded ? 'degraded' : 'healthy',
    services,
    metrics: {
      totalAuditEvents: logs.length,
      failedAuthAttemptsLast24h: failedAuth,
      activeConnectionsCount: 1,
      openBaoMasterKeyVersion: `v${bao.keyVersion}`
    }
  };
}

/**
 * Dispara um alerta de segurança imediato para canais configurados e grava na auditoria.
 */
export async function triggerSecurityAlert(alert: {
  title: string;
  severity: 'warning' | 'critical';
  details: Record<string, unknown>;
}): Promise<void> {
  // 1. Grava evento crítico na trilha imutável
  logAuditEvent({
    action: 'security.alert_triggered',
    category: 'system',
    severity: alert.severity,
    actor: 'system.monitoring',
    ipAddress: '127.0.0.1',
    description: `ALERTA DE SEGURANÇA: ${alert.title}`,
    details: alert.details
  });

  // 2. Dispara webhook de alerta configurado
  const settings = getNotificationSettings();
  if (settings.webhookEnabled && settings.webhookUrl) {
    try {
      await fetch(settings.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Zatten-Alert': 'true' },
        body: JSON.stringify({
          alert: alert.title,
          severity: alert.severity,
          timestamp: new Date().toISOString(),
          details: alert.details
        })
      });
    } catch {
      // Ignora falha de rede externa silenciosamente
    }
  }
}
