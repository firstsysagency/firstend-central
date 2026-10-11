/**
 * GERENCIADOR DE CONEXÕES VIA VARIÁVEIS DE AMBIENTE (COOLIFY DEPLOY)
 * Central Privada de Conexões Zatten — Firstsys
 * 
 * Permite que as chaves da Zatten sejam provisionadas diretamente nas
 * variáveis de ambiente do Coolify / VPS, eliminando 100% de qualquer trânsito
 * de segredos pelo navegador ou front-end.
 */

import fs from 'fs';
import path from 'path';
import { secretsVault } from './secretsVault.js';
import { logAuditEvent } from '../../src/lib/audit.js';

export interface EnvConnectionConfig {
  id: string;
  name: string;
  apiKey: string;
  environment: 'production' | 'staging';
  organizationId?: string;
}

export interface SanitizedConnectionMeta {
  id: string;
  organizationId: string;
  name: string;
  status: 'active' | 'invalid' | 'paused' | 'revoked';
  environment: 'production' | 'staging';
  source: 'coolify_env' | 'manual';
  managedBy: 'coolify' | 'manual';
  keyVersion: number;
  lastValidatedAt: string;
  lastUsedAt: string | null;
  createdBy: string;
  createdAt: string;
}

const MOCK_DB_PATH = path.join(process.cwd(), 'server', 'db.json');

/**
 * Lê e analisa todas as chaves Zatten definidas nas variáveis de ambiente do Coolify.
 * Suporta três formatos flexíveis:
 * 1. Chave Única: ZATTEN_API_KEY (com ZATTEN_CONNECTION_NAME e ZATTEN_ENVIRONMENT opcionais)
 * 2. Múltiplas Chaves via JSON: ZATTEN_CONNECTIONS_JSON='[{"id":"conn_vendas","name":"Vendas","apiKey":"zat_..."},...]'
 * 3. Múltiplas Chaves por Prefixo: ZATTEN_KEY_<NOME>=zat_live_... ou ZATTEN_CONNECTION_<NOME>=zat_...
 */
export function parseEnvConnections(): EnvConnectionConfig[] {
  const configs: EnvConnectionConfig[] = [];
  const defaultOrgId = process.env.DEFAULT_ORG_ID || 'org_firstsys_prod';

  // --- FORMATO 1: Chave Única Padrão (ZATTEN_API_KEY ou ZATTEN_DEFAULT_KEY) ---
  const singleKey = process.env.ZATTEN_API_KEY || process.env.ZATTEN_DEFAULT_KEY;
  if (singleKey && singleKey.trim().length >= 10) {
    const connId = process.env.ZATTEN_CONNECTION_ID || 'conn_coolify_principal';
    const connName = process.env.ZATTEN_CONNECTION_NAME || 'Zatten Conexão Principal (Coolify)';
    const envType = (process.env.ZATTEN_ENVIRONMENT === 'staging' ? 'staging' : 'production') as 'production' | 'staging';

    configs.push({
      id: connId.trim(),
      name: connName.trim(),
      apiKey: singleKey.trim(),
      environment: envType,
      organizationId: defaultOrgId
    });
  }

  // --- FORMATO 2: Múltiplas Conexões via JSON (ZATTEN_CONNECTIONS_JSON) ---
  const jsonConnections = process.env.ZATTEN_CONNECTIONS_JSON;
  if (jsonConnections) {
    try {
      const parsed = JSON.parse(jsonConnections);
      if (Array.isArray(parsed)) {
        for (const item of parsed) {
          if (item && item.apiKey && typeof item.apiKey === 'string') {
            const rawId = item.id || `conn_coolify_${item.name ? item.name.toLowerCase().replace(/[^a-z0-9]/g, '_') : Math.random().toString(36).substring(2, 7)}`;
            configs.push({
              id: String(rawId),
              name: String(item.name || 'Conexão Zatten Coolify'),
              apiKey: String(item.apiKey).trim(),
              environment: item.environment === 'staging' ? 'staging' : 'production',
              organizationId: item.organizationId || defaultOrgId
            });
          }
        }
      }
    } catch (err) {
      console.warn('[EnvConnections] Aviso: Falha ao interpretar ZATTEN_CONNECTIONS_JSON:', err);
    }
  }

  // --- FORMATO 3: Múltiplas Chaves por Prefixo Dinâmico (ZATTEN_KEY_* ou ZATTEN_CONNECTION_*) ---
  for (const [key, value] of Object.entries(process.env)) {
    if (!value || typeof value !== 'string' || value.length < 10) continue;

    let suffix = '';
    if (key.startsWith('ZATTEN_KEY_') && key !== 'ZATTEN_KEY_NAME') {
      suffix = key.replace('ZATTEN_KEY_', '');
    } else if (key.startsWith('ZATTEN_CONNECTION_') && key !== 'ZATTEN_CONNECTION_NAME' && key !== 'ZATTEN_CONNECTION_ID') {
      suffix = key.replace('ZATTEN_CONNECTION_', '');
    }

    if (suffix) {
      const slug = suffix.toLowerCase().replace(/[^a-z0-9]/g, '_');
      const connId = `conn_coolify_${slug}`;
      const friendlyName = `Zatten ${suffix.charAt(0) + suffix.slice(1).toLowerCase().replace(/_/g, ' ')} (Coolify)`;

      // Evita duplicatas se já adicionado
      if (!configs.some(c => c.id === connId)) {
        configs.push({
          id: connId,
          name: friendlyName,
          apiKey: value.trim(),
          environment: 'production',
          organizationId: defaultOrgId
        });
      }
    }
  }

  return configs;
}

/**
 * Inicializa e sincroniza as conexões das variáveis de ambiente com o cofre criptográfico
 * e com o catálogo de conexões do sistema.
 */
export async function syncEnvConnections(): Promise<SanitizedConnectionMeta[]> {
  const configs = parseEnvConnections();
  const synchronized: SanitizedConnectionMeta[] = [];

  if (configs.length === 0) {
    return synchronized;
  }

  console.log(`🔒 [Coolify Env] Sincronizando ${configs.length} conexão(ões) Zatten provisionada(s) via Variáveis de Ambiente...`);

  // Carrega ou inicializa a base de conexões
  let db: any = { users: [], connections: [], mcpPermissions: [] };
  if (fs.existsSync(MOCK_DB_PATH)) {
    try {
      db = JSON.parse(fs.readFileSync(MOCK_DB_PATH, 'utf8'));
    } catch (e) {
      console.warn('Erro ao ler DB mock', e);
    }
  }
  if (!db.connections) db.connections = [];

  for (const config of configs) {
    const orgId = config.organizationId || 'org_firstsys_prod';
    
    // 1. Armazena a chave com criptografia no cofre (OpenBao Transit / AES-256-GCM)
    // A chave NUNCA é gravada em texto plano no banco de dados.
    const secretMeta = await secretsVault.storeZattenKey({
      connectionId: config.id,
      rawApiKey: config.apiKey,
      organizationId: orgId,
      actor: 'coolify_environment_provisioner'
    });

    const nowIso = new Date().toISOString();

    // 2. Procura se a conexão já existe no banco
    const existingIndex = db.connections.findIndex((c: any) => c.id === config.id);

    const connectionRecord = {
      id: config.id,
      organizationId: orgId,
      name: config.name,
      secretRef: secretMeta.secretRef,
      keyVersion: secretMeta.keyVersion,
      status: 'active' as const,
      environment: config.environment,
      source: 'coolify_env' as const,
      managedBy: 'coolify' as const,
      lastValidatedAt: nowIso,
      lastUsedAt: existingIndex >= 0 ? db.connections[existingIndex].lastUsedAt : null,
      createdBy: 'coolify (env)',
      createdAt: existingIndex >= 0 ? db.connections[existingIndex].createdAt : nowIso,
      updatedAt: nowIso
    };

    if (existingIndex >= 0) {
      db.connections[existingIndex] = {
        ...db.connections[existingIndex],
        ...connectionRecord
      };
    } else {
      db.connections.push(connectionRecord);
    }

    logAuditEvent({
      actor: 'system (coolify env)',
      action: 'connection.env_provisioned',
      category: 'keys',
      severity: 'info',
      description: `Conexão '${config.name}' (${config.id}) provisionada/atualizada automaticamente via Variáveis de Ambiente do Coolify.`,
      ipAddress: '127.0.0.1'
    });

    synchronized.push({
      id: connectionRecord.id,
      organizationId: connectionRecord.organizationId,
      name: connectionRecord.name,
      status: connectionRecord.status,
      environment: connectionRecord.environment,
      source: connectionRecord.source,
      managedBy: connectionRecord.managedBy,
      keyVersion: connectionRecord.keyVersion,
      lastValidatedAt: connectionRecord.lastValidatedAt,
      lastUsedAt: connectionRecord.lastUsedAt,
      createdBy: connectionRecord.createdBy,
      createdAt: connectionRecord.createdAt
    });
  }

  // Persiste a base atualizada
  try {
    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));
  } catch (err) {
    console.error('[EnvConnections] Falha ao persistir metadados das conexões:', err);
  }

  console.log(`✅ [Coolify Env] ${synchronized.length} conexão(ões) Zatten ativada(s) e protegida(s) no cofre com sucesso.`);
  return synchronized;
}
