/**
 * SANITIZADOR E MECANISMO DE MERGE SEGURO DE TEMPLATES ZATTEN
 * Central Privada de Conexões Zatten — Firstsys
 * Blindagem total de chaves de API, credenciais e headers confidenciais
 */

const REDACTED_MARKER = '<redacted>';

const SENSITIVE_KEY_NAMES = new Set([
  'api_key',
  'apikey',
  'secret',
  'token',
  'password',
  'elevenlabs_api_key',
  'eleven_labs_api_key',
  'auth_token',
  'access_token',
  'private_key'
]);

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'x-api-key',
  'cookie',
  'token',
  'secret',
  'password',
  'proxy-authorization',
  'x-auth-token'
]);

/**
 * Sanitiza recursivamente um objeto ou template, substituindo qualquer segredo por "<redacted>"
 */
export function sanitizeTemplateSecrets(obj: any): any {
  if (obj === null || obj === undefined) return obj;

  if (typeof obj === 'string') {
    // Sanitiza query strings como ?key=XYZ ou ?token=XYZ ou ?api_key=XYZ
    return obj.replace(/([?&](?:api[_-]?key|token|secret|key|password)=)[^&]+/gi, `$1${REDACTED_MARKER}`);
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeTemplateSecrets(item));
  }

  if (typeof obj === 'object') {
    const sanitized: Record<string, any> = {};

    for (const [key, val] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();

      // Checagem de headers de requisições em ferramentas ou webhooks
      if (lowerKey === 'headers' && typeof val === 'object' && val !== null && !Array.isArray(val)) {
        const sanitizedHeaders: Record<string, any> = {};
        for (const [hKey, hVal] of Object.entries(val as Record<string, any>)) {
          if (SENSITIVE_HEADER_NAMES.has(hKey.toLowerCase())) {
            sanitizedHeaders[hKey] = REDACTED_MARKER;
          } else {
            sanitizedHeaders[hKey] = sanitizeTemplateSecrets(hVal);
          }
        }
        sanitized[key] = sanitizedHeaders;
        continue;
      }

      // Checagem direta de chaves sensíveis (api_key, token, password, etc)
      if (SENSITIVE_KEY_NAMES.has(lowerKey) || lowerKey.endsWith('_api_key') || lowerKey.endsWith('apikey')) {
        sanitized[key] = REDACTED_MARKER;
        continue;
      }

      sanitized[key] = sanitizeTemplateSecrets(val);
    }

    return sanitized;
  }

  return obj;
}

/**
 * Valida se um payload de patch tenta injetar strings "<redacted>" ou chaves de autenticação vazias
 */
export function validateNoRedactedOrEmptySecrets(patch: any, path: string = ''): void {
  if (!patch || typeof patch !== 'object') return;

  for (const [key, val] of Object.entries(patch)) {
    const currentPath = path ? `${path}.${key}` : key;
    const lowerKey = key.toLowerCase();

    if (typeof val === 'string') {
      if (val.trim() === REDACTED_MARKER) {
        throw new Error(`Tentativa inválida de enviar '${REDACTED_MARKER}' no campo '${currentPath}'. Segredos existentes não devem ser reenviados.`);
      }

      if (SENSITIVE_KEY_NAMES.has(lowerKey) && val.trim() === '') {
        throw new Error(`Não é permitido enviar credencial vazia para '${currentPath}'.`);
      }
    }

    if (lowerKey === 'headers' && typeof val === 'object' && val !== null) {
      for (const [hKey, hVal] of Object.entries(val as Record<string, any>)) {
        if (typeof hVal === 'string' && (hVal.trim() === REDACTED_MARKER || (SENSITIVE_HEADER_NAMES.has(hKey.toLowerCase()) && hVal.trim() === ''))) {
          throw new Error(`Header de autenticação inválido ou vazio para '${currentPath}.${hKey}'.`);
        }
      }
    }

    if (typeof val === 'object' && val !== null) {
      validateNoRedactedOrEmptySecrets(val, currentPath);
    }
  }
}

/**
 * Realiza merge cuidadoso sobre o template bruto atual preservando todos os segredos existentes
 */
export function mergeTemplatePatch(
  rawTemplate: Record<string, any>,
  patch: Record<string, any>
): {
  finalTemplate: Record<string, any>;
  changes: string[];
  notes: string[];
  orphans: any[];
  ambiguous: any[];
} {
  const finalTemplate = JSON.parse(JSON.stringify(rawTemplate));
  const changes: string[] = [];
  const notes: string[] = [];
  const orphans: any[] = [];
  const ambiguous: any[] = [];

  // Allowlist de blocos permitidos para modificação
  const ALLOWED_PATCH_KEYS = new Set([
    'prompt',
    'model',
    'settings',
    'skills',
    'tools',
    'properties',
    'tags',
    'columns',
    'departments',
    'automations',
    'flows',
    'langchain'
  ]);

  for (const [key, patchVal] of Object.entries(patch)) {
    if (!ALLOWED_PATCH_KEYS.has(key)) {
      notes.push(`Bloco ignorado por não pertencer à allowlist de configuração: '${key}'.`);
      continue;
    }

    // Caso 1: Blocos base simples (prompt, etc)
    if (typeof patchVal === 'string' || typeof patchVal === 'number' || typeof patchVal === 'boolean') {
      if (finalTemplate[key] !== patchVal) {
        finalTemplate[key] = patchVal;
        changes.push(`Bloco '${key}' atualizado.`);
      }
      continue;
    }

    // Caso 2: Objeto model (preservando api_key caso não seja atualizada de forma válida)
    if (key === 'model' && typeof patchVal === 'object' && patchVal !== null) {
      const existingApiKey = finalTemplate.model?.api_key;
      finalTemplate.model = {
        ...finalTemplate.model,
        ...patchVal
      };
      // Preserva a API key existente se não foi enviada uma nova
      if (existingApiKey && (!patchVal.api_key || patchVal.api_key === REDACTED_MARKER)) {
        finalTemplate.model.api_key = existingApiKey;
      }
      changes.push("Configurações do modelo LLM ('model') atualizadas.");
      continue;
    }

    // Caso 3: Objeto settings (preservando tracing api_key)
    if (key === 'settings' && typeof patchVal === 'object' && patchVal !== null) {
      const existingTracingKey = finalTemplate.settings?.tracing?.api_key;
      finalTemplate.settings = {
        ...finalTemplate.settings,
        ...patchVal,
        tracing: {
          ...(finalTemplate.settings?.tracing || {}),
          ...((patchVal as any).tracing || {})
        }
      };
      if (existingTracingKey && (!(patchVal as any).tracing?.api_key || (patchVal as any).tracing?.api_key === REDACTED_MARKER)) {
        finalTemplate.settings.tracing.api_key = existingTracingKey;
      }
      changes.push("Configurações gerais ('settings') atualizadas.");
      continue;
    }

    // Caso 4: Arrays de entidades identificadas por slug (columns, tags, properties, departments)
    if (['columns', 'tags', 'properties', 'departments'].includes(key) && Array.isArray(patchVal)) {
      const existingList = Array.isArray(finalTemplate[key]) ? [...finalTemplate[key]] : [];
      for (const item of patchVal) {
        if (!item || typeof item !== 'object') continue;
        const slug = (item as any).slug || (item as any).id;
        if (!slug) {
          ambiguous.push({ block: key, item, reason: 'Item sem slug ou ID identificável.' });
          continue;
        }

        const existingIdx = existingList.findIndex(e => (e.slug === slug || e.id === slug));
        if (existingIdx >= 0) {
          existingList[existingIdx] = { ...existingList[existingIdx], ...item };
          changes.push(`Item em '${key}' com slug '${slug}' atualizado.`);
        } else {
          existingList.push(item);
          changes.push(`Novo item adicionado em '${key}' com slug '${slug}'.`);
        }
      }
      finalTemplate[key] = existingList;
      continue;
    }

    // Caso 5: langchain.config ou outros blocos de objeto complexo
    if (typeof patchVal === 'object' && patchVal !== null) {
      finalTemplate[key] = {
        ...(finalTemplate[key] || {}),
        ...patchVal
      };
      changes.push(`Bloco '${key}' mesclado com sucesso.`);
    }
  }

  // Verificação básica de integridade / itens órfãos
  if (Array.isArray(finalTemplate.columns) && Array.isArray(finalTemplate.departments)) {
    const validDeptIds = new Set(finalTemplate.departments.map((d: any) => d.id || d.slug));
    for (const col of finalTemplate.columns) {
      if (col.department_id && !validDeptIds.has(col.department_id)) {
        orphans.push({
          type: 'column_department_missing',
          column: col.slug || col.name,
          department_id: col.department_id,
          message: `Coluna '${col.name || col.slug}' aponta para departamento inexistente '${col.department_id}'.`
        });
      }
    }
  }

  notes.push('Merge de template executado com retenção estrita de credenciais pré-existentes.');

  return {
    finalTemplate,
    changes,
    notes,
    orphans,
    ambiguous
  };
}
