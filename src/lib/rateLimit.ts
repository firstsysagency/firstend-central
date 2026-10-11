/**
 * RATE LIMITING MULTI-NÍVEL (TOKEN BUCKET / SLIDING WINDOW)
 * Central de Chaves Zatten — Defesa contra Ataques de Força Bruta e DoS (Checklist 296)
 */

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetSeconds: number;
  retryAfterSeconds?: number;
}

interface BucketRecord {
  tokens: number;
  lastRefill: number;
}

const memoryBuckets = new Map<string, BucketRecord>();

/**
 * Aplica controle de taxa com algoritmo Token Bucket em memória.
 * @param key Identificador único (IP, Org ID, ou Chave de Acesso)
 * @param maxCapacity Capacidade máxima de requisições na janela
 * @param refillRatePerSecond Taxa de reposição de tokens por segundo
 */
export function checkRateLimit(
  key: string,
  maxCapacity = 60,
  refillRatePerSecond = 1
): RateLimitResult {
  const now = Date.now();
  let bucket = memoryBuckets.get(key);

  if (!bucket) {
    bucket = { tokens: maxCapacity, lastRefill: now };
    memoryBuckets.set(key, bucket);
  }

  // Reposição de tokens proporcional ao tempo decorrido
  const elapsedSeconds = (now - bucket.lastRefill) / 1000;
  bucket.tokens = Math.min(maxCapacity, bucket.tokens + elapsedSeconds * refillRatePerSecond);
  bucket.lastRefill = now;

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return {
      allowed: true,
      limit: maxCapacity,
      remaining: Math.floor(bucket.tokens),
      resetSeconds: Math.ceil((maxCapacity - bucket.tokens) / refillRatePerSecond)
    };
  }

  const waitSeconds = Math.ceil((1 - bucket.tokens) / refillRatePerSecond);
  return {
    allowed: false,
    limit: maxCapacity,
    remaining: 0,
    resetSeconds: waitSeconds,
    retryAfterSeconds: waitSeconds
  };
}

/**
 * Rate limit específico para tentativas de login e validação MFA (Janela estrita: 5 tentativas por minuto).
 */
export function checkAuthRateLimit(actorKey: string): RateLimitResult {
  return checkRateLimit(`auth:${actorKey}`, 5, 5 / 60);
}

/**
 * Rate limit para chamadas de API da Zatten (1 requisição por segundo por conexão).
 */
export function checkConnectionRateLimit(connectionId: string): RateLimitResult {
  return checkRateLimit(`conn:${connectionId}`, 3, 1);
}
