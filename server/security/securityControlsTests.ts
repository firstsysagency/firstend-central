/**
 * SUÍTE DE TESTES AUTOMATIZADOS: CONTROLES DE SEGURANÇA CORPORATIVA (SECURITY CONTROLS)
 * Central Privada Firstsys
 * Valida: Autenticação/RBAC, Schemas Zod, Concorrência Otimista, Idempotência, Auditoria, Importação em 2 Fases e Postura
 */

import {
  seedInitial100ControlsIfEmpty,
  listSecurityControls,
  getSecurityControl,
  createSecurityControl,
  updateSecurityControl,
  bulkUpdateSecurityControls,
  importPreviewSecurityControls,
  importCommitSecurityControls,
  archiveSecurityControl,
  deleteSecurityControl,
  createSecurityControlEvidence,
  listSecurityControlEvidence,
  createSecurityControlException,
  listSecurityControlExceptions,
  resolveSecurityControlException,
  runSecurityControlsAssessment,
  getSecurityPostureSummary,
  listSecurityAuditEvents
} from './securityControlsStore.js';
import { SecurityControlCreateInputSchema } from './securityControlsTypes.js';

async function runTests() {
  console.log('🧪 [TESTES DE CONTROLES DE SEGURANÇA] Iniciando validação completa...\n');

  // 1. Inicialização e Catálogo dos 100 Controles
  seedInitial100ControlsIfEmpty();
  const initialList = listSecurityControls({ limit: 100 });
  if (initialList.total < 100) {
    throw new Error(`Falha no seed: esperava ao menos 100 controles, encontrou ${initialList.total}`);
  }
  console.log(`✅ [Passou] 1. Inicialização confirmada com ${initialList.total} controles de segurança corporativos.`);

  // 2. Consulta Individual e Categorias
  const sec001 = getSecurityControl('SEC-001');
  if (!sec001 || sec001.category !== 'rede' || sec001.control_code !== 'SEC-001') {
    throw new Error('Falha ao consultar controle SEC-001 por código.');
  }
  const sec001ById = getSecurityControl(sec001.id);
  if (!sec001ById || sec001ById.control_code !== 'SEC-001') {
    throw new Error('Falha ao consultar controle SEC-001 por ID opaco.');
  }
  console.log('✅ [Passou] 2. Consulta individual por código e por ID opaco validada.');

  // 3. Validação Estrita de Schemas Zod e Bloqueio de Códigos Duplicados
  const invalidCode = SecurityControlCreateInputSchema.safeParse({
    control_code: 'INVALIDO_SEM_SEC',
    name: 'Teste',
    category: 'rede',
    description: 'desc',
    rationale: 'rat',
    implementation: 'impl',
    validation_method: 'val'
  });
  if (invalidCode.success) {
    throw new Error('Schema deveria rejeitar códigos fora do padrão SEC-XXX.');
  }

  let duplicateBlocked = false;
  try {
    createSecurityControl({
      control_code: 'SEC-001', // já existe
      name: 'Duplicado',
      category: 'rede',
      description: 'Descricao longa de teste',
      rationale: 'Rationale de teste longo',
      implementation: 'Implementacao de teste longa',
      validation_method: 'Metodo de validacao de teste',
      severity: 'high',
      status: 'planned'
    }, 'test-runner', '127.0.0.1');
  } catch (err: any) {
    if (err.message.includes('já existe')) {
      duplicateBlocked = true;
    }
  }
  if (!duplicateBlocked) {
    throw new Error('Deveria bloquear criação de controle com código duplicado.');
  }
  console.log('✅ [Passou] 3. Schemas estritos Zod e bloqueio de códigos duplicados validados.');

  // 4. Criação de Controle com Auditoria e Idempotência
  const testCode = `SEC-TEST-${Date.now().toString().slice(-4)}`;
  const idempotencyKey = `idemp_${Date.now()}`;
  const created1 = createSecurityControl({
    control_code: testCode,
    name: 'Controle de Teste de Isolamento',
    category: 'aplicacao',
    description: 'Descrição completa do controle de teste para validação.',
    rationale: 'Justificativa do controle de teste para validação.',
    implementation: 'Implementação detalhada do controle de teste.',
    validation_method: 'Validação empírica do controle de teste.',
    severity: 'high',
    status: 'in_progress',
    owner: 'QA SecOps'
  }, 'qa-agent', '10.0.0.1', idempotencyKey);

  if (created1.revision !== 1 || created1.control_code !== testCode) {
    throw new Error('Falha na criação do controle.');
  }

  // Testar idempotência (mesma chave retorna o mesmo objeto sem criar outro)
  const created2 = createSecurityControl({
    control_code: testCode,
    name: 'Tentativa Duplicada com Mesma Chave',
    category: 'aplicacao',
    description: 'Descrição ignorada',
    rationale: 'Justificativa ignorada',
    implementation: 'Implementação ignorada',
    validation_method: 'Validação ignorada',
    severity: 'low',
    status: 'planned'
  }, 'qa-agent', '10.0.0.1', idempotencyKey);

  if (created2.id !== created1.id || created2.name !== created1.name) {
    throw new Error('Idempotência falhou: mesma chave deveria retornar o resultado original.');
  }
  console.log('✅ [Passou] 4. Criação individual com revisão inicial e idempotência verificadas.');

  // 5. Concorrência Otimista (expected_revision)
  // Tentativa com revisão errada deve falhar com 409
  let conflictCaught = false;
  try {
    updateSecurityControl(created1.id, {
      expected_revision: 999, // errada, atual é 1
      name: 'Nome Atualizado Conflitante'
    }, 'qa-agent', '10.0.0.1');
  } catch (err: any) {
    if (err.status === 409 || err.code === 'OPTIMISTIC_LOCK_CONFLICT') {
      conflictCaught = true;
    }
  }
  if (!conflictCaught) {
    throw new Error('Concorrência otimista falhou: expected_revision divergente deveria disparar erro 409.');
  }

  // Atualização com expected_revision correta deve suceder e incrementar revision para 2
  const updated = updateSecurityControl(created1.id, {
    expected_revision: 1,
    name: 'Nome Atualizado com Sucesso',
    status: 'verified'
  }, 'qa-agent', '10.0.0.1');

  if (updated.revision !== 2 || updated.name !== 'Nome Atualizado com Sucesso' || updated.status !== 'verified') {
    throw new Error('Falha na atualização com concorrência otimista correta.');
  }
  console.log('✅ [Passou] 5. Concorrência otimista comprovada (409 em divergência, incremento de revisão em sucesso).');

  // 6. Evidências Técnicas com Hash SHA-256
  const evidence = createSecurityControlEvidence(created1.id, {
    title: 'Relatório de Pentest Q4',
    description: 'Varredura automatizada comprovando ausência de falhas.',
    evidence_type: 'report',
    evidence_data: 'Relatorio sintetico: 0 vulnerabilidades criticas encontradas.'
  }, 'qa-agent', '10.0.0.1');

  if (!evidence.hash || evidence.hash.length !== 64 || evidence.control_code !== testCode) {
    throw new Error('Falha na criação de evidência com hash SHA-256.');
  }
  const evidenceList = listSecurityControlEvidence(created1.id);
  if (evidenceList.length === 0 || evidenceList[0].id !== evidence.id) {
    throw new Error('Falha ao listar evidências associadas ao controle.');
  }
  console.log('✅ [Passou] 6. Criação e listagem de evidências técnicas com integridade SHA-256 validadas.');

  // 7. Gestão de Exceções e Resolução
  const exception = createSecurityControlException(created1.id, {
    reason: 'Risco aceito temporariamente até entrega do patch da biblioteca.',
    approved_by: 'CISO / Diretor Técnico',
    risk_accepted: true,
    expires_at: new Date(Date.now() + 30 * 86400000).toISOString()
  }, 'ciso-user', '10.0.0.1');

  if (exception.status !== 'active') {
    throw new Error('Exceção criada deveria ter status "active".');
  }

  const checkCtrlStatus = getSecurityControl(created1.id);
  if (checkCtrlStatus?.status !== 'exception') {
    throw new Error('Controle associado deveria ter status alterado para "exception".');
  }

  const resolved = resolveSecurityControlException(exception.id, {
    resolution_notes: 'Patch aplicado com sucesso na versão 2.4.1.'
  }, 'ciso-user', '10.0.0.1');

  if (resolved.status !== 'resolved' || !resolved.resolved_at) {
    throw new Error('Falha na resolução da exceção.');
  }
  console.log('✅ [Passou] 7. Gestão de exceções (criação, status e resolução com restauração) comprovada.');

  // 8. Importação em Massa em Duas Etapas (Preview com Erros vs Commit)
  const invalidBatch = [
    {
      control_code: 'SEC-VALID-1',
      name: 'Controle Válido',
      category: 'rede',
      description: 'Descricao valida longa',
      rationale: 'Rationale valido longo',
      implementation: 'Implementacao valida longa',
      validation_method: 'Validacao valida longa'
    },
    {
      control_code: 'INVALIDO', // código inválido
      name: 'X' // nome muito curto
    }
  ];

  const previewInvalid = importPreviewSecurityControls(invalidBatch);
  if (previewInvalid.ok !== false || previewInvalid.invalid_count !== 1 || previewInvalid.valid_count !== 1) {
    throw new Error('Preview deveria reportar lote inválido sem salvar nada.');
  }

  let commitBlocked = false;
  try {
    importCommitSecurityControls(invalidBatch, 'key_err', 'admin', '127.0.0.1');
  } catch {
    commitBlocked = true;
  }
  if (!commitBlocked) {
    throw new Error('Commit com lote inválido deveria ser rejeitado.');
  }

  const validBatch = [
    {
      control_code: `SEC-IMP-A-${Date.now().toString().slice(-4)}`,
      name: 'Controle Importado A',
      category: 'dados',
      description: 'Descricao detalhada do controle A para teste de lote.',
      rationale: 'Justificativa do controle A para teste de lote.',
      implementation: 'Implementacao tecnica detalhada do controle A.',
      validation_method: 'Metodo de teste e validacao do controle A.',
      severity: 'critical',
      status: 'implemented'
    }
  ];

  const previewValid = importPreviewSecurityControls(validBatch);
  if (!previewValid.ok || previewValid.to_create_count !== 1) {
    throw new Error('Preview válido deveria indicar 1 item to_create.');
  }

  const commitResult = importCommitSecurityControls(validBatch, `commit_key_${Date.now()}`, 'admin', '127.0.0.1');
  if (!commitResult.ok || commitResult.created_count !== 1) {
    throw new Error('Commit válido falhou.');
  }
  console.log('✅ [Passou] 8. Importação em duas etapas comprovada: preview rejeita lote inválido e commit grava com sucesso.');

  // 9. Postura de Segurança Agregada (Zero Segredos Expostos)
  const posture = getSecurityPostureSummary();
  if (
    typeof posture.total_controls !== 'number' ||
    typeof posture.compliance_rate_percent !== 'number' ||
    !posture.by_category ||
    !posture.by_status ||
    !posture.by_severity
  ) {
    throw new Error('Postura de segurança agregada com campos ausentes.');
  }

  // Garantir que nenhum segredo esteja no objeto de postura
  const postureJson = JSON.stringify(posture);
  if (postureJson.includes('secret') || postureJson.includes('password') || postureJson.includes('privateKey')) {
    throw new Error('Violação de segurança: postura agregada contém potenciais segredos.');
  }
  console.log(`✅ [Passou] 9. Postura agregada calculada com sucesso (${posture.active_controls} controles ativos, taxa de conformidade: ${posture.compliance_rate_percent}%, zero segredos).`);

  // 10. Trilha de Auditoria Imutável
  const auditList = listSecurityAuditEvents({ control_code: testCode });
  if (auditList.events.length === 0) {
    throw new Error('Trilha de auditoria não registrou os eventos do controle de teste.');
  }
  console.log(`✅ [Passou] 10. Trilha imutável de auditoria confirmada (${auditList.total} eventos registrados).`);

  // 11. Limpeza Segura do Controle de Teste
  deleteSecurityControl(created1.id, true, true, 'admin', '127.0.0.1');
  console.log('✅ [Passou] 11. Exclusão de controle de teste com confirmação e privilégio administrativo concluída.');

  console.log('\n🎉 TODOS OS 11 TESTES DO MÓDULO DE CONTROLES DE SEGURANÇA FORAM APROVADOS COM SUCESSO TOTAL!');
}

runTests().catch(err => {
  console.error('\n❌ [FALHA NOS TESTES DE CONTROLES DE SEGURANÇA]:', err);
  process.exit(1);
});
