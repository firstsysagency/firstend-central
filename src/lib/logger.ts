/**
 * LOGGER ESTRUTURADO COM REDACTION AUTOMÁTICO DE SEGREDOS
 * Central de Chaves Zatten — Proteção Militar contra Vazamento de Credenciais (Checklist 294)
 */

const SENSITIVE_KEYS = new Set([
  'authorization',
  'x-api-key',
  'api_key',
  'apikey',
  'key',
  'secret',
  'token',
  'password',
  'cookie',
  'set-cookie',
  'x-vault-token',
  'ciphertext',
  'apiKeyCiphertext',
  'webhook_secret',
  'root_token',
  'unseal_key'
]);

const ZATTEN_KEY_REGEX = /zat_[a-zA-Z0-9_-]{20,}/g;
const JWT_REGEX = /eyJ[a-zA-Z0-9_-]{15,}\.eyJ[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}/g;

/**
 * Sanitiza recursivamente objetos, arrays e strings eliminando valores confidenciais.
 */
export function redactSensitiveData(data: unknown): unknown {
  if (typeof data === 'string') {
    let sanitized = data.replace(ZATTEN_KEY_REGEX, 'zat_[REDACTED]');
    sanitized = sanitized.replace(JWT_REGEX, '[JWT_REDACTED]');
    return sanitized;
  }

  if (Array.isArray(data)) {
    return data.map(redactSensitiveData);
  }

  if (data !== null && typeof data === 'object') {
    const cleaned: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      if (SENSITIVE_KEYS.has(key.toLowerCase())) {
        cleaned[key] = '[REDACTED]';
      } else {
        cleaned[key] = redactSensitiveData(value);
      }
    }
    return cleaned;
  }

  return data;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface StructuredLog {
  timestamp: string;
  level: LogLevel;
  module: string;
  message: string;
  context?: unknown;
}

class SecureLogger {
  private formatLog(level: LogLevel, module: string, message: string, context?: unknown): StructuredLog {
    return {
      timestamp: new Date().toISOString(),
      level,
      module,
      message,
      context: context ? redactSensitiveData(context) : undefined
    };
  }

  public info(module: string, message: string, context?: unknown): void {
    const payload = this.formatLog('info', module, message, context);
    console.info(`[${payload.timestamp}] [INFO] [${payload.module}]: ${payload.message}`, payload.context ?? '');
  }

  public warn(module: string, message: string, context?: unknown): void {
    const payload = this.formatLog('warn', module, message, context);
    console.warn(`[${payload.timestamp}] [WARN] [${payload.module}]: ${payload.message}`, payload.context ?? '');
  }

  public error(module: string, message: string, context?: unknown): void {
    const payload = this.formatLog('error', module, message, context);
    console.error(`[${payload.timestamp}] [ERROR] [${payload.module}]: ${payload.message}`, payload.context ?? '');
  }
}

export const secureLogger = new SecureLogger();
