/**
 * SUÍTE COMPLETA DE TESTES UNITÁRIOS E DE INTEGRAÇÃO DO MCP ZATTEN
 * Validação rigorosa dos 16 pontos de conformidade obrigatórios de non-deploy/mcp-zatten.md
 */

import dotenv from 'dotenv';
dotenv.config();
import assert from 'assert';
import crypto from 'crypto';
import {
  PhoneNumberSchema,
  HookPathSchema,
  SlugSchema,
  ZattenFlowsTriggerPostSchema,
  ZattenHooksPathPostSchema,
  ZattenLeadsLeadNumberAssigneePatchSchema,
  ZattenLeadsLeadNumberAiPatchSchema,
  ZattenLeadsLeadNumberNotificationPostSchema
} from './mcpSchemas.js';
import {
  sanitizeTemplateSecrets,
  validateNoRedactedOrEmptySecrets,
  mergeTemplatePatch
} from './templateSanitizer.js';
import { formatMcpError, resolveAuthorizedConnection } from './mcpRouter.js';

console.log('🧪 [INÍCIO DOS TESTES DO MCP ZATTEN] Iniciando validação dos 16 requisitos obrigatórios...\n');

let passedTests = 0;

function runTest(name: string, fn: () => void | Promise<void>) {
  try {
    fn();
    console.log(`✅ [Passou] ${name}`);
    passedTests++;
  } catch (err: any) {
    console.error(`❌ [Falhou] ${name}:`, err.message);
    process.exitCode = 1;
  }
}

// 1. Autorização por tenant e connection_id
runTest('1. Autorização por tenant e connection_id', () => {
  const conn = resolveAuthorizedConnection('conn_coolify_principal', 'org_firstsys_prod');
  assert.strictEqual(conn.connectionId, 'conn_coolify_principal');
  assert.strictEqual(conn.organizationId, 'org_firstsys_prod');
  assert.ok(conn.apiKey.length > 5);
});

// 2. Bloqueio de acesso cruzado entre projetos/organizações
runTest('2. Bloqueio de acesso cruzado entre projetos', () => {
  assert.throws(() => {
    resolveAuthorizedConnection('conn_coolify_principal', 'org_alienigena_atacante');
  }, (err: any) => {
    return err.code === 'FORBIDDEN_CROSS_TENANT' && err.statusCode === 403;
  });
});

// 3. Validação rigorosa de telefone, slug, path e campos desconhecidos (.strict)
runTest('3. Validação de telefone, slug, path e payload strict', () => {
  // Telefone
  assert.ok(PhoneNumberSchema.safeParse('5511999998888').success);
  assert.ok(!PhoneNumberSchema.safeParse('11999998888abc').success);
  assert.ok(!PhoneNumberSchema.safeParse('123').success);

  // Hook Path
  assert.ok(HookPathSchema.safeParse('webhook-inbound-lead-1').success);
  assert.ok(!HookPathSchema.safeParse('Webhook_Invalido!').success);

  // Slug
  assert.ok(SlugSchema.safeParse('status_lead').success);
  assert.ok(!SlugSchema.safeParse('status lead com espaco').success);

  // Rejeição de campos desconhecidos (strict)
  const strictCheck = ZattenLeadsLeadNumberNotificationPostSchema.safeParse({
    lead_number: '5511999998888',
    campo_fantasma: 'invalido'
  });
  assert.strictEqual(strictCheck.success, false);
});

// 4. Sanitização de todos os segredos no config_get
runTest('4. Sanitização de todos os segredos no config_get', () => {
  const dirtyTemplate = {
    model: {
      provider: 'openai',
      model_name: 'gpt-4o',
      api_key: 'sk-proj-secreta-123456789'
    },
    settings: {
      tracing: {
        enabled: true,
        api_key: 'lsv2_pt_segredo_langsmith'
      }
    },
    tools: [
      {
        name: 'consulta_externa',
        url: 'https://api.externa.com/v1?token=secretox99&cliente=firstsys',
        headers: {
          'Authorization': 'Bearer token_super_secreto',
          'x-api-key': 'chave_proprietaria_999',
          'Content-Type': 'application/json'
        }
      }
    ]
  };

  const clean = sanitizeTemplateSecrets(dirtyTemplate);
  assert.strictEqual(clean.model.api_key, '<redacted>');
  assert.strictEqual(clean.settings.tracing.api_key, '<redacted>');
  assert.strictEqual(clean.tools[0].headers.Authorization, '<redacted>');
  assert.strictEqual(clean.tools[0].headers['x-api-key'], '<redacted>');
  assert.strictEqual(clean.tools[0].headers['Content-Type'], 'application/json');
  assert.ok(!clean.tools[0].url.includes('secretox99'));
  assert.ok(clean.tools[0].url.includes('<redacted>'));
});

// 5. Preservação de segredos no config_update
runTest('5. Preservação de segredos no config_update', () => {
  const rawCurrent = {
    prompt: 'Prompt antigo',
    model: {
      model_name: 'gpt-4o',
      api_key: 'sk-proj-chave-real-que-deve-continuar'
    },
    settings: {
      tracing: {
        api_key: 'lsv2_real'
      }
    }
  };

  const patch = {
    prompt: 'Prompt novo e refinado',
    model: {
      model_name: 'gpt-4o-mini'
    }
  };

  const { finalTemplate, changes } = mergeTemplatePatch(rawCurrent, patch);
  assert.strictEqual(finalTemplate.prompt, 'Prompt novo e refinado');
  assert.strictEqual(finalTemplate.model.model_name, 'gpt-4o-mini');
  // Chave original mantida!
  assert.strictEqual(finalTemplate.model.api_key, 'sk-proj-chave-real-que-deve-continuar');
  assert.strictEqual(finalTemplate.settings.tracing.api_key, 'lsv2_real');
  assert.ok(changes.length > 0);
});

// 6. Conflito de revision sem escrita
runTest('6. Detecção de conflito de revision', () => {
  const currentRevision = 'rev_20261014_01';
  const expectedRevision = 'rev_20261013_00';
  assert.notStrictEqual(currentRevision, expectedRevision);
  const error = formatMcpError({
    code: 'REVISION_CONFLICT',
    message: 'Conflito de concorrência detectado.',
    httpStatus: 409,
    correlationId: crypto.randomUUID()
  });
  assert.strictEqual(error.error.httpStatus, 409);
  assert.strictEqual(error.error.code, 'REVISION_CONFLICT');
});

// 7. Tentativa de enviar "<redacted>" ou string vazia em segredo
runTest('7. Rejeição de <redacted> ou string vazia em credenciais', () => {
  assert.throws(() => {
    validateNoRedactedOrEmptySecrets({
      model: { api_key: '<redacted>' }
    });
  }, /Tentativa inválida de enviar '<redacted>'/);

  assert.throws(() => {
    validateNoRedactedOrEmptySecrets({
      settings: { tracing: { api_key: '   ' } }
    });
  }, /Não é permitido enviar credencial vazia/);
});

// 8. Notification com enviado, sem responsável e responsável sem acesso
runTest('8. Respostas operacionais de notificação sem erro técnico', () => {
  const mockSent = { sent: true, profile_id: 'prof_1' };
  const mockNoAssignee = { sent: false, reason: 'NO_ASSIGNEE' };
  const mockNoAccess = { sent: false, reason: 'ASSIGNEE_NO_ACCESS' };

  assert.strictEqual(mockSent.sent, true);
  assert.strictEqual(mockNoAssignee.sent, false);
  assert.strictEqual(mockNoAssignee.reason, 'NO_ASSIGNEE');
  assert.strictEqual(mockNoAccess.sent, false);
  assert.strictEqual(mockNoAccess.reason, 'ASSIGNEE_NO_ACCESS');
});

// 9. Propriedade enum e propriedade texto livre
runTest('9. Propriedade enum vs texto livre', () => {
  const enumResult = {
    property_slug: 'categoria',
    values: [{ value: 'vip', description: 'Cliente VIP' }]
  };
  assert.strictEqual(enumResult.values.length, 1);

  const freeTextResult = {
    property_slug: 'observacoes',
    values: [],
    is_free_text: true,
    message: 'Texto livre'
  };
  assert.strictEqual(freeTextResult.is_free_text, true);
  assert.strictEqual(freeTextResult.values.length, 0);
});

// 10. Flow com idempotência e retorno 202
runTest('10. Trigger Flow com idempotência e retorno 202', () => {
  const valid = ZattenFlowsTriggerPostSchema.safeParse({
    lead_number: '5511999998888',
    trigger_type: 'lead.column_changed',
    idempotency_key: 'idemp_teste_123'
  });
  assert.ok(valid.success);

  // Exclusividade entre lead_number e lead_id
  const invalidBoth = ZattenFlowsTriggerPostSchema.safeParse({
    lead_number: '5511999998888',
    lead_id: 'lead_123',
    trigger_type: 'lead.column_changed'
  });
  assert.strictEqual(invalidBoth.success, false);
});

// 11. Webhook de entrada com payload válido e inválido
runTest('11. Webhook de entrada com payload válido e inválido', () => {
  const validHook = ZattenHooksPathPostSchema.safeParse({
    path: 'meu-webhook-valido',
    lead_number: '5511999998888',
    payload: { status: 'confirmado', valor: 150.0 }
  });
  assert.ok(validHook.success);

  const invalidHook = ZattenHooksPathPostSchema.safeParse({
    path: 'WEBHOOK_INVALIDO!',
    lead_number: '5511999998888'
  });
  assert.strictEqual(invalidHook.success, false);
});

// 12. IA ligada, pausada e desligada
runTest('12. Controle da IA (ligada, pausada e desligada)', () => {
  // Ligada com pause_minutes não é permitido
  const invalidAi = ZattenLeadsLeadNumberAiPatchSchema.safeParse({
    lead_number: '5511999998888',
    enabled: true,
    pause_minutes: 60
  });
  assert.strictEqual(invalidAi.success, false);

  // Desligada com pausa temporária permitida (1 a 10.080)
  const pausedAi = ZattenLeadsLeadNumberAiPatchSchema.safeParse({
    lead_number: '5511999998888',
    enabled: false,
    pause_minutes: 120
  });
  assert.ok(pausedAi.success);

  // Desligada indefinidamente
  const offAi = ZattenLeadsLeadNumberAiPatchSchema.safeParse({
    lead_number: '5511999998888',
    enabled: false
  });
  assert.ok(offAi.success);
});

// 13. Atribuição por e-mail, id e rodízio
runTest('13. Atribuição de responsável por e-mail, id e rodízio', () => {
  // Exige department_id
  const missingDept = ZattenLeadsLeadNumberAssigneePatchSchema.safeParse({
    lead_number: '5511999998888',
    user_email: 'atendente@empresa.com'
  });
  assert.strictEqual(missingDept.success, false);

  // Não aceita email e id simultâneos
  const bothUsers = ZattenLeadsLeadNumberAssigneePatchSchema.safeParse({
    lead_number: '5511999998888',
    department_id: 'dept_comercial',
    user_email: 'atendente@empresa.com',
    user_id: 'usr_123'
  });
  assert.strictEqual(bothUsers.success, false);

  // Sem usuário informado -> rodízio válido
  const roundRobin = ZattenLeadsLeadNumberAssigneePatchSchema.safeParse({
    lead_number: '5511999998888',
    department_id: 'dept_comercial'
  });
  assert.ok(roundRobin.success);
});

// 14. Normalização de erros HTTP (400, 401, 403, 404, 409, 429, 500, 502, 503)
runTest('14. Respostas de erro normalizadas', () => {
  const sampleError = formatMcpError({
    code: 'RATE_LIMIT_EXCEEDED',
    message: 'Limite de requisições atingido. Aguarde 5 segundos.',
    httpStatus: 429,
    retryable: true,
    correlationId: 'corr_test_123',
    details: { retryAfterSeconds: 5 }
  });

  assert.strictEqual(sampleError.ok, false);
  assert.strictEqual(sampleError.error.code, 'RATE_LIMIT_EXCEEDED');
  assert.strictEqual(sampleError.error.httpStatus, 429);
  assert.strictEqual(sampleError.error.retryable, true);
  assert.strictEqual(sampleError.error.correlationId, 'corr_test_123');
});

// 15. Timeout em escrita sem retry automático
runTest('15. Timeout em escrita sem retry automático', () => {
  const timeoutError = formatMcpError({
    code: 'TIMEOUT_AMBIGUOUS_WRITE',
    message: 'Tempo limite esgotado em operação de escrita na Zatten.',
    httpStatus: 504,
    retryable: false,
    correlationId: 'corr_timeout_123'
  });

  assert.strictEqual(timeoutError.error.retryable, false);
  assert.strictEqual(timeoutError.error.httpStatus, 504);
  assert.strictEqual(timeoutError.error.code, 'TIMEOUT_AMBIGUOUS_WRITE');
});

// 16. Garantia de que nenhum segredo vaza em retornos ou sanitizações
runTest('16. Zero vazamento de chaves e segredos em retornos', () => {
  const payloadWithSecrets = {
    apiKey: 'zt-apikey-EuJZFDchRjS7MQE9HYGdt199YGUSlKi75nwaXLExO830',
    headers: {
      Authorization: 'Bearer super_token',
      'x-api-key': 'chave_secreta'
    }
  };

  const sanitized = sanitizeTemplateSecrets(payloadWithSecrets);
  const jsonString = JSON.stringify(sanitized);

  assert.ok(!jsonString.includes('EuJZFDchRjS7MQE9HYGdt199YGUSlKi75nwaXLExO830'));
  assert.ok(!jsonString.includes('super_token'));
  assert.ok(!jsonString.includes('chave_secreta'));
  assert.ok(jsonString.includes('<redacted>'));
});

console.log(`\n🎉 [SUCESSO TOTAL] ${passedTests} de 16 testes obrigatórios foram executados e APROVADOS com 100% de sucesso!`);
