/**
 * CLIENTE SEGURO DA API ZATTEN COM FILA E RATE LIMITING DE 1 REQ/S POR CONEXÃO
 * Central Privada de Conexões Zatten — Firstsys
 * A chave Zatten é consumida em memória apenas pelo tempo da chamada e jamais exposta
 */

import { secretsVault } from '../vault/secretsVault.js';
import { logAuditEvent } from '../../src/lib/audit.js';

export interface ZattenRequestOptions {
  connectionId: string;
  secretRef: string;
  endpoint: string; // Ex: /v1/leads, /v1/messages
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  idempotencyKey?: string;
  isWriteOperation?: boolean;
}

export interface ZattenResponse<T = unknown> {
  success: boolean;
  status: number;
  data?: T;
  error?: string;
}

// Fila em memória por conexão para garantir o limite estrito de 1 requisição por segundo por chave Zatten
interface QueueTask {
  execute: () => Promise<void>;
}

class ZattenRateLimitedQueue {
  private queues: Map<string, QueueTask[]> = new Map();
  private processing: Set<string> = new Set();
  private readonly minIntervalMs: number = 1000; // 1 req/s por conexão Zatten

  public async enqueue<T>(connectionId: string, taskFn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const task: QueueTask = {
        execute: async () => {
          try {
            const result = await taskFn();
            resolve(result);
          } catch (err) {
            reject(err);
          }
        }
      };

      const connQueue = this.queues.get(connectionId) || [];
      connQueue.push(task);
      this.queues.set(connectionId, connQueue);

      this.processNext(connectionId);
    });
  }

  private async processNext(connectionId: string): Promise<void> {
    if (this.processing.has(connectionId)) return;

    const connQueue = this.queues.get(connectionId);
    if (!connQueue || connQueue.length === 0) return;

    this.processing.add(connectionId);
    const nextTask = connQueue.shift();

    if (nextTask) {
      try {
        await nextTask.execute();
      } finally {
        // Aguarda 1 segundo antes de liberar a próxima requisição desta mesma conexão
        setTimeout(() => {
          this.processing.delete(connectionId);
          this.processNext(connectionId);
        }, this.minIntervalMs);
      }
    } else {
      this.processing.delete(connectionId);
    }
  }
}

const connectionQueue = new ZattenRateLimitedQueue();

export class ZattenApiClient {
  private baseUrl: string;

  constructor() {
    this.baseUrl = process.env.ZATTEN_API_BASE_URL || 'https://api.zatten.com';
  }

  /**
   * Executa chamada segura à API Zatten com rate limit de 1 req/s, timeout e tratamento de 400/401/429
   */
  public async executeRequest<T = unknown>(options: ZattenRequestOptions): Promise<ZattenResponse<T>> {
    const {
      connectionId,
      secretRef,
      endpoint,
      method,
      body,
      idempotencyKey,
      isWriteOperation
    } = options;

    return connectionQueue.enqueue(connectionId, async () => {
      // 1. Descriptografa a chave Zatten em memória temporária
      const rawApiKey = await secretsVault.resolveZattenKey(secretRef);

      const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
      const headers: Record<string, string> = {
        'x-api-key': rawApiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      };

      if (idempotencyKey) {
        headers['Idempotency-Key'] = idempotencyKey;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // Timeout estrito de 10 segundos

      try {
        const response = await fetch(url, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        // Tratamento seguro de códigos HTTP da Zatten:
        if (response.status === 401) {
          // Chave revogada ou inválida na Zatten
          logAuditEvent({
            actor: 'system',
            action: 'zatten.auth.failed',
            category: 'security',
            severity: 'critical',
            description: `Chave da conexão ${connectionId} rejeitada pela Zatten (401 Unauthorized).`,
            ipAddress: '127.0.0.1'
          });

          return {
            success: false,
            status: 401,
            error: 'Chave Zatten inválida ou revogada na plataforma de origem.'
          };
        }

        if (response.status === 429) {
          logAuditEvent({
            actor: 'system',
            action: 'zatten.ratelimit.hit',
            category: 'api_usage',
            severity: 'warning',
            description: `Rate limit alcançado na API Zatten para a conexão ${connectionId} (429 Too Many Requests).`,
            ipAddress: '127.0.0.1'
          });

          return {
            success: false,
            status: 429,
            error: 'Controle de taxa da Zatten excedido. Tente novamente em instantes.'
          };
        }

        if (!response.ok) {
          const errText = await response.text();
          // Sanitização de erro: nunca expor headers nem dados brutos
          return {
            success: false,
            status: response.status,
            error: `Erro retornado pela API Zatten (HTTP ${response.status}): ${errText.slice(0, 150)}`
          };
        }

        const data = await response.json() as T;

        logAuditEvent({
          actor: 'system',
          action: isWriteOperation ? 'zatten.write.executed' : 'zatten.read.executed',
          category: 'api_usage',
          severity: 'info',
          description: `Chamada ${method} ${endpoint} executada com sucesso para conexão ${connectionId}`,
          ipAddress: '127.0.0.1'
        });

        return {
          success: true,
          status: response.status,
          data
        };
      } catch (err: unknown) {
        clearTimeout(timeoutId);
        const isAbort = (err as any)?.name === 'AbortError';
        return {
          success: false,
          status: isAbort ? 408 : 500,
          error: isAbort ? 'Tempo limite de requisição à Zatten esgotado (Timeout 10s).' : 'Falha na conexão com a Zatten.'
        };
      }
    });
  }
}

export const zattenClient = new ZattenApiClient();
