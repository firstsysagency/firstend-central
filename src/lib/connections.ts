export interface Connection {
  id: string;
  name: string;
  status: 'active' | 'revoked' | 'invalid' | 'paused';
  environment: 'production' | 'staging' | 'development';
  description: string;
  lastUsed: string;
  createdAt: string;
  apiKey?: string;
  source?: 'coolify_env' | 'manual';
  managedBy?: 'coolify' | 'manual';
  keyVersion?: number;
  lastValidatedAt?: string;
}

const STORAGE_KEY = 'zatten_connections_v1';

const INITIAL_CONNECTIONS: Connection[] = [];

export function getStoredConnections(): Connection[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_CONNECTIONS));
      return INITIAL_CONNECTIONS;
    }
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed;
    }
    return INITIAL_CONNECTIONS;
  } catch (error) {
    console.error('Falha ao carregar conexões do localStorage:', error);
    return INITIAL_CONNECTIONS;
  }
}

/**
 * Sincroniza as conexões com o backend (que lê as variáveis de ambiente do Coolify).
 */
export async function fetchBackendConnections(): Promise<Connection[]> {
  try {
    const token = localStorage.getItem('token') || localStorage.getItem('zatten_session');
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch('/api/connections', { headers });
    if (res.ok) {
      const data = await res.json();
      if (data.success && Array.isArray(data.connections)) {
        const mapped: Connection[] = data.connections.map((c: any) => ({
          id: c.id,
          name: c.name,
          status: c.status,
          environment: c.environment || 'production',
          description: c.source === 'coolify_env' 
            ? 'Conexão provisionada com segurança via Variáveis de Ambiente no Coolify.' 
            : 'Conexão cadastrada via Central Zatten.',
          lastUsed: c.lastUsedAt ? new Date(c.lastUsedAt).toLocaleString('pt-BR') : 'Nunca utilizada',
          createdAt: c.createdAt ? new Date(c.createdAt).toLocaleDateString('pt-BR') : new Date().toLocaleDateString('pt-BR'),
          source: c.source || 'manual',
          managedBy: c.managedBy || 'manual',
          keyVersion: c.keyVersion || 1,
          lastValidatedAt: c.lastValidatedAt
        }));

        if (mapped.length > 0) {
          saveConnections(mapped);
          return mapped;
        }
      }
    }
  } catch (err) {
    console.warn('[Connections] Erro ao sincronizar com backend:', err);
  }
  return getStoredConnections();
}

export function saveConnections(connections: Connection[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(connections));
  } catch (error) {
    console.error('Falha ao salvar conexões no localStorage:', error);
  }
}

export function addConnection(data: {
  name: string;
  environment?: 'production' | 'staging' | 'development';
  description?: string;
  apiKey?: string;
}): Connection {
  const current = getStoredConnections();
  const randomSuffix = Math.random().toString(36).substring(2, 8);
  const newConn: Connection = {
    id: `conn_${randomSuffix}`,
    name: data.name,
    status: 'active',
    environment: data.environment || 'production',
    description: data.description || 'Conexão cadastrada via painel Key Manager.',
    lastUsed: 'Nunca utilizada',
    createdAt: new Date().toISOString().split('T')[0],
    apiKey: data.apiKey
  };

  const updated = [newConn, ...current];
  saveConnections(updated);
  return newConn;
}

export function updateConnection(id: string, updates: Partial<Connection>): Connection[] {
  const current = getStoredConnections();
  const updated = current.map(item => {
    if (item.id === id) {
      return { ...item, ...updates };
    }
    return item;
  });
  saveConnections(updated);
  return updated;
}

export function deleteConnection(id: string): Connection[] {
  const current = getStoredConnections();
  const updated = current.filter(item => item.id !== id);
  saveConnections(updated);
  return updated;
}
