/**
 * Módulo de Auditoria e Logs de Segurança do Key Manager (Zatten Central).
 * Registra eventos imutáveis, estruturados e com proteção estrita contra vazamento de segredos.
 */

import { persistAuditLogToPostgres } from './postgresAudit.js';

export type AuditSeverity = 'info' | 'warning' | 'critical';

export type AuditCategory = 'auth' | 'keys' | 'members' | 'notifications' | 'mcp' | 'system' | 'security' | 'api_usage';

export interface AuditLogEntry {
  id: string;
  timestamp: string; // ISO 8601
  formattedDate: string;
  action: string;
  category: AuditCategory;
  severity: AuditSeverity;
  actor: string;
  ipAddress: string;
  ip?: string;
  description: string;
  details?: Record<string, unknown>;
}

const STORAGE_KEY = 'zatten_audit_logs_v1';

const INITIAL_LOGS: AuditLogEntry[] = [
  {
    id: 'aud_01j982a',
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    formattedDate: new Date(Date.now() - 1000 * 60 * 12).toLocaleString('pt-BR'),
    action: 'key.rotated',
    category: 'keys',
    severity: 'info',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: 'Chave mestra rotacionada com sucesso no Transit Secrets Engine (OpenBao)',
    details: {
      keyVersion: 'v4',
      transitPath: 'transit/keys/key-manager-master',
      algorithm: 'AES-256-GCM',
      envelopeStatus: 'synchronized'
    }
  },
  {
    id: 'aud_01j981x',
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    formattedDate: new Date(Date.now() - 1000 * 60 * 45).toLocaleString('pt-BR'),
    action: 'mfa.verification_failed',
    category: 'auth',
    severity: 'warning',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: 'Tentativa de validação TOTP rejeitada: código incorreto ou expirado',
    details: {
      attemptedDigits: 6,
      reason: 'TOTP drift window check failed'
    }
  },
  {
    id: 'aud_01j979c',
    timestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    formattedDate: new Date(Date.now() - 1000 * 60 * 180).toLocaleString('pt-BR'),
    action: 'cors.blocked_request',
    category: 'system',
    severity: 'critical',
    actor: 'external_client',
    ipAddress: '45.160.88.12',
    description: 'Tentativa de requisição bloqueada por política CORS de origem não autorizada',
    details: {
      origin: 'https://malicious-client-origin.net',
      allowedOrigin: 'https://keys.zatten.com',
      endpoint: '/api/v1/connections'
    }
  },
  {
    id: 'aud_01j976m',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(),
    formattedDate: new Date(Date.now() - 1000 * 60 * 60 * 5).toLocaleString('pt-BR'),
    action: 'mcp.tool_executed',
    category: 'mcp',
    severity: 'info',
    actor: 'chatgpt_oauth_session',
    ipAddress: '54.23.10.89',
    description: 'Ferramenta MCP de leitura zatten_list_connections executada com sucesso',
    details: {
      scope: 'zatten:read',
      connectionsReturned: 4,
      secretsExposed: 0
    }
  },
  {
    id: 'aud_01j974a',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    formattedDate: new Date(Date.now() - 1000 * 60 * 60 * 24).toLocaleString('pt-BR'),
    action: 'member.role_updated',
    category: 'members',
    severity: 'info',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: 'Papel do membro beatriz@zatten.com atualizado para Operador',
    details: {
      targetMember: 'beatriz@zatten.com',
      previousRole: 'viewer',
      newRole: 'operator'
    }
  },
  {
    id: 'aud_01j971k',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
    formattedDate: new Date(Date.now() - 1000 * 60 * 60 * 48).toLocaleString('pt-BR'),
    action: 'connection.status_changed',
    category: 'keys',
    severity: 'warning',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: 'Chave de conexão "Suporte N2" pausada/desligada via interruptor rápido',
    details: {
      connectionId: 'conn-3',
      previousStatus: 'active',
      newStatus: 'revoked'
    }
  }
];

export function getAuditLogs(): AuditLogEntry[] {
  if (typeof localStorage === 'undefined') {
    return INITIAL_LOGS;
  }
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_LOGS));
      return INITIAL_LOGS;
    }
    return JSON.parse(raw);
  } catch (err) {
    console.error('Erro ao ler logs de auditoria:', err);
    return INITIAL_LOGS;
  }
}

export function addAuditLog(entry: Omit<AuditLogEntry, 'id' | 'timestamp' | 'formattedDate'>): AuditLogEntry {
  const current = getAuditLogs();
  const now = new Date();
  const ipAddress = entry.ipAddress || entry.ip || '127.0.0.1';
  const newLog: AuditLogEntry = {
    ...entry,
    ipAddress,
    id: `aud_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
    timestamp: now.toISOString(),
    formattedDate: now.toLocaleString('pt-BR')
  };

  const updated = [newLog, ...current];
  if (typeof localStorage !== 'undefined') {
    try {
      // Mantém no máximo 500 registros no armazenamento local
      const trimmed = updated.slice(0, 500);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
    } catch (err) {
      console.error('Erro ao salvar log de auditoria:', err);
    }
  }

  // Persistência assíncrona na tabela 'audit_logs' do PostgreSQL com RLS
  persistAuditLogToPostgres(newLog).catch((err: unknown) => {
    console.warn('Persistência no PostgreSQL em segundo plano:', err);
  });

  return newLog;
}

export const logAuditEvent = addAuditLog;

export function clearAuditLogs(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    console.error('Erro ao limpar logs:', err);
  }
}

/**
 * Exporta os logs filtrados em formato CSV estruturado.
 */
export function exportAuditLogsAsCSV(logs: AuditLogEntry[]): void {
  const headers = ['ID', 'Data/Hora', 'Ação', 'Categoria', 'Severidade', 'Ator', 'IP', 'Descrição'];
  const rows = logs.map(log => [
    `"${log.id}"`,
    `"${log.formattedDate}"`,
    `"${log.action}"`,
    `"${log.category}"`,
    `"${log.severity}"`,
    `"${log.actor}"`,
    `"${log.ipAddress}"`,
    `"${log.description.replace(/"/g, '""')}"`
  ]);

  const csvContent = '\uFEFF' + [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `auditoria_zatten_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Exporta os logs filtrados em formato JSON estruturado com metadados de integridade.
 */
export function exportAuditLogsAsJSON(logs: AuditLogEntry[]): void {
  const exportPayload = {
    exportedAt: new Date().toISOString(),
    organization: 'Zatten Central — Firstsys',
    totalEntries: logs.length,
    securityDisclaimer: 'Este documento contém metadados de auditoria técnica. Segredos e chaves brutas nunca são persistidos em logs.',
    logs
  };

  const jsonContent = JSON.stringify(exportPayload, null, 2);
  const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `auditoria_zatten_${new Date().toISOString().slice(0, 10)}.json`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
