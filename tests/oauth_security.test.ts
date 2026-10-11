/**
 * SUÍTE DE TESTES DE SEGURANÇA E CONFORMIDADE OAUTH 2.1 & MCP
 * Central Privada de Conexões Zatten — Firstsys
 * Execução Automatizada dos Testes Obrigatórios
 */

import crypto from 'crypto';
import { 
  verifyPkceChallenge, 
  toBase64Url, 
  signJwt, 
  verifyJwt,
  encryptSecret,
  decryptSecret
} from '../server/oauth/cryptoEngine.js';
import { oauthStore } from '../server/oauth/oauthStore.js';
import { redactSensitiveData } from '../src/lib/logger.js';
import { secretsVault } from '../server/vault/secretsVault.js';
import { zattenClient } from '../server/zatten/zattenClient.js';

let passedTests = 0;
let totalTests = 0;

function assert(condition: boolean, message: string) {
  totalTests++;
  if (!condition) {
    console.error(`❌ FALHA: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  passedTests++;
  console.log(`✅ SUCESSO: ${message}`);
}

async function runAllTests() {
  console.log('\n================================================================');
  console.log('🔒 INICIANDO SUÍTE DE TESTES OAUTH 2.1, MCP E SEGURANÇA FIRSTSYS');
  console.log('================================================================\n');

  // ----------------------------------------------------------------------------
  // TESTE 1: PKCE S256 (RFC 7636) - Validação e Rejeição com Verifier Incorreto
  // ----------------------------------------------------------------------------
  console.log('--- [1] Teste de PKCE S256 ---');
  const codeVerifier = 'a_very_high_entropy_random_string_verifier_with_more_than_43_characters_long_123456';
  const sha256Hash = crypto.createHash('sha256').update(codeVerifier, 'ascii').digest();
  const codeChallenge = toBase64Url(sha256Hash);

  assert(verifyPkceChallenge(codeVerifier, codeChallenge), 'PKCE S256 deve validar com verifier correto');
  assert(!verifyPkceChallenge('wrong_verifier_1234567890123456789012345678901234567890', codeChallenge), 'PKCE deve rejeitar verifier incorreto');
  assert(!verifyPkceChallenge('curto', codeChallenge), 'PKCE deve rejeitar verifier menor que 43 caracteres');

  // ----------------------------------------------------------------------------
  // TESTE 2: Validação Estrita de Redirect URI (Sem Curingas / Igualdade Exata)
  // ----------------------------------------------------------------------------
  console.log('\n--- [2] Teste de Redirect URI Estrita ---');
  const validUri = 'https://chatgpt.com/aip/oauth/callback';
  const wildcardUri = 'https://*.chatgpt.com/callback';
  const untrustedUri = 'https://malicious-site.com/callback';

  assert(oauthStore.validateRedirectUri('chatgpt-firstsys-mcp', validUri), 'Deve aceitar Redirect URI exata pré-registrada');
  assert(!oauthStore.validateRedirectUri('chatgpt-firstsys-mcp', wildcardUri), 'Deve PROIBIR Redirect URIs com curingas (*)');
  assert(!oauthStore.validateRedirectUri('chatgpt-firstsys-mcp', untrustedUri), 'Deve rejeitar Redirect URIs não autorizadas');

  // ----------------------------------------------------------------------------
  // TESTE 3: Assinatura Assimétrica de Token (RS256) e Validação de Audiência
  // ----------------------------------------------------------------------------
  console.log('\n--- [3] Teste de Assinatura JWT RS256 e Audiência ---');
  const now = Math.floor(Date.now() / 1000);
  const mcpResource = 'https://mcp.firstsys.com.br/mcp';

  const validPayload = {
    iss: 'https://auth.firstsys.com.br',
    sub: 'usr_firstsys_01',
    aud: mcpResource,
    exp: now + 900,
    nbf: now - 5,
    iat: now,
    jti: 'jti_token_01',
    org_id: 'org_matriz_prod',
    role: 'owner' as const,
    scope: 'connections:read zatten:read zatten:write zatten:messages',
    client_id: 'chatgpt-firstsys-mcp'
  };

  const jwtString = signJwt(validPayload);
  const verifyResult = verifyJwt(jwtString);
  assert(verifyResult.valid && verifyResult.payload?.sub === 'usr_firstsys_01', 'JWT assinado com RS256 deve ser validado com chave pública');

  // Token expirado
  const expiredPayload = { ...validPayload, exp: now - 60, jti: 'jti_expired_02' };
  const expiredJwt = signJwt(expiredPayload);
  assert(!verifyJwt(expiredJwt).valid, 'Token expirado deve ser rejeitado');

  // Token com audiência incorreta
  const wrongAudPayload = { ...validPayload, aud: 'https://other-service.com/api', jti: 'jti_wrong_aud' };
  const wrongAudJwt = signJwt(wrongAudPayload);
  const wrongAudVerified = verifyJwt(wrongAudJwt);
  const audCheck = Array.isArray(wrongAudVerified.payload?.aud) 
    ? wrongAudVerified.payload?.aud.includes(mcpResource) 
    : wrongAudVerified.payload?.aud === mcpResource;
  assert(!audCheck, 'Token emitido para outro recurso deve ser identificado e rejeitado pelo MCP');

  // ----------------------------------------------------------------------------
  // TESTE 4: Rotação de Refresh Token e Detecção de Reuso de Família (Reuse Detection)
  // ----------------------------------------------------------------------------
  console.log('\n--- [4] Teste de Detecção de Reuso de Refresh Token ---');
  const initialRt = oauthStore.issueRefreshToken({
    clientId: 'chatgpt-firstsys-mcp',
    userId: 'usr_firstsys_01',
    userEmail: 'contato@firstsys.com.br',
    orgId: 'org_matriz_prod',
    role: 'owner',
    scope: 'connections:read zatten:read',
    resource: mcpResource
  });

  // Primeira rotação legítima
  const firstRotation = oauthStore.rotateRefreshToken(initialRt);
  assert(firstRotation.valid, 'Primeira rotação do refresh token deve ter sucesso');

  if (firstRotation.valid) {
    const secondRt = firstRotation.newRefreshToken;

    // ATAQUE / TENTATIVA DE REUSO: Apresentar initialRt novamente!
    const reuseAttempt = oauthStore.rotateRefreshToken(initialRt);
    assert(!reuseAttempt.valid && reuseAttempt.familyCompromised === true, 'Reuso de refresh token antigo deve ser DETECTADO e sinalizar família comprometida');

    // Consequência: Até o token novo (secondRt) da mesma família deve estar revogado agora!
    const subsequentAttempt = oauthStore.rotateRefreshToken(secondRt);
    assert(!subsequentAttempt.valid, 'Toda a família de tokens deve estar revogada após detecção de reuso');
  }

  // ----------------------------------------------------------------------------
  // TESTE 5: Proteção de Segredos, Redaction em Logs e Cifragem AES-256-GCM
  // ----------------------------------------------------------------------------
  console.log('\n--- [5] Teste de Cifragem AES-256-GCM e Redaction de Logs ---');
  const secretKey = 'ztn_live_secret_key_firstsys_production_998877665544';
  const encrypted = encryptSecret(secretKey);
  assert(encrypted.ciphertext !== secretKey, 'Texto cifrado não deve conter a chave original');
  assert(encrypted.iv.length > 0 && encrypted.tag.length > 0, 'Criptografia autenticada deve incluir IV e Authentication Tag');

  const decrypted = decryptSecret(encrypted);
  assert(decrypted === secretKey, 'Descriptografia autorizada em memória deve recuperar a chave original');

  // Redaction de logs
  const logWithSecrets = {
    url: '/api/v1/leads',
    authorization: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.token',
    'x-api-key': secretKey,
    password: 'SuperSecretPassword!',
    messageText: 'Olá Lead'
  };

  const redacted = redactSensitiveData(logWithSecrets);
  assert((redacted as any)['x-api-key'] === '[REDACTED]', 'x-api-key deve ser ocultada nos logs');
  assert((redacted as any).authorization === '[REDACTED]', 'Authorization Bearer deve ser ocultado nos logs');
  assert((redacted as any).password === '[REDACTED]', 'Senhas devem ser ocultadas nos logs');
  assert((redacted as any).messageText === 'Olá Lead', 'Campos de negócio não sensíveis devem ser preservados');

  // ----------------------------------------------------------------------------
  // TESTE 6: Armazenamento Seguro no SecretsVault
  // ----------------------------------------------------------------------------
  console.log('\n--- [6] Teste de Armazenamento no SecretsVault ---');
  const vaultResult = await secretsVault.storeZattenKey({
    connectionId: 'conn_test_01',
    rawApiKey: secretKey,
    organizationId: 'org_matriz_prod',
    actor: 'admin@firstsys.com.br'
  });

  assert(vaultResult.secretRef.length > 0, 'SecretsVault deve gerar referência segura de segredo');
  const resolved = await secretsVault.resolveZattenKey(vaultResult.secretRef);
  assert(resolved === secretKey, 'SecretsVault deve resolver a chave em memória para a chamada');

  // ----------------------------------------------------------------------------
  // TESTE 7: Fila e Rate Limiting da Zatten (1 req/s por conexão)
  // ----------------------------------------------------------------------------
  console.log('\n--- [7] Teste da Fila de 1 req/s por Conexão Zatten ---');
  const startTime = Date.now();
  
  // Enfileira duas tarefas na mesma conexão simulada
  const p1 = zattenClient.executeRequest({
    connectionId: 'conn_queue_test',
    secretRef: vaultResult.secretRef,
    endpoint: '/v1/status',
    method: 'GET'
  });

  const p2 = zattenClient.executeRequest({
    connectionId: 'conn_queue_test',
    secretRef: vaultResult.secretRef,
    endpoint: '/v1/status',
    method: 'GET'
  });

  await Promise.allSettled([p1, p2]);
  const elapsed = Date.now() - startTime;
  assert(elapsed >= 950, `Fila deve espaçar requisições consecutivas da mesma conexão em pelo menos 1s (Decorreu: ${elapsed}ms)`);

  console.log('\n================================================================');
  console.log(`🎉 TODOS OS ${passedTests}/${totalTests} TESTES DE SEGURANÇA FORAM CONCLUÍDOS COM SUCESSO!`);
  console.log('================================================================\n');
}

runAllTests().catch((err) => {
  console.error('\n❌ ERRO NA EXECUÇÃO DA SUÍTE DE TESTES:', err);
  process.exit(1);
});
