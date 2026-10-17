import assert from 'assert';
import {
  seedInitialSecurity
} from './seedSecurity.js';
import {
  listSecurityItems,
  getSecurityItem,
  createSecurityItem,
  updateSecurityItem,
  deleteSecurityItem,
  addSecurityTag,
  removeSecurityTag,
  listSecurityFiles,
  getSecurityFile,
  saveSecurityFile,
  deleteSecurityFile,
  restoreSecurityFile,
  listSecurityAuditLogs,
  sanitizeSecurityPath
} from './securityStore.js';

console.log('🧪 Iniciando Suíte de Testes Automatizados de Segurança Corporativa Firstsys...');

// 1. Teste do Seed Inicial
console.log('1. Testando seedInitialSecurity()...');
seedInitialSecurity();
const items = listSecurityItems();
assert(items.length >= 8, `Esperado pelo menos 8 métodos de segurança no catálogo, obtido ${items.length}`);
console.log(`✅ Seed inicial verificado: ${items.length} tecnologias de segurança ativas.`);

// 2. Teste de Busca por Slug e ID
console.log('2. Testando getSecurityItem()...');
const helmetItem = getSecurityItem('hardening-headers-http');
assert(helmetItem !== null, 'Item "hardening-headers-http" deve ser encontrado');
assert.strictEqual(helmetItem?.category, 'hardening');
assert.strictEqual(helmetItem?.severity, 'alto');
console.log('✅ getSecurityItem por slug validado com sucesso.');

// 3. Teste de Sanitização de Caminhos e Proteção Anti-Traversal
console.log('3. Testando sanitizeSecurityPath() e defesas de path traversal...');
assert.throws(() => sanitizeSecurityPath('../etc/passwd'), /Violação de segurança/);
assert.throws(() => sanitizeSecurityPath('/absoluto/arquivo.md'), /Caminho deve ser relativo/);
assert.throws(() => sanitizeSecurityPath('credentials.json'), /potenciais segredos/);
assert.throws(() => sanitizeSecurityPath('segredo.env'), /estritamente proibida/);
assert.throws(() => sanitizeSecurityPath('malware.exe'), /estritamente proibida/);
assert.strictEqual(sanitizeSecurityPath('diretrizes/regras.json'), 'diretrizes/regras.json');
console.log('✅ Defesas anti-traversal e extensões permitidas validadas.');

// 4. Teste de Criação de Novo Item de Segurança
console.log('4. Testando createSecurityItem()...');
const testSlug = `teste-sec-${Date.now()}`;
const createdItem = createSecurityItem({
  name: 'Controle de Acesso Baseado em Atributos (ABAC)',
  description: 'Controle dinâmico de permissões por contexto e atributos do usuário. Implementação com políticas JSON em tempo real.',
  category: 'autenticacao',
  severity: 'medio',
  complianceStandards: ['NIST SP 800-53', 'ISO 27001'],
  tags: ['abac', 'permissoes', 'autorizacao'],
  initialContent: '# ABAC Firstsys\n\nDiretrizes de autorização baseada em atributos.'
}, 'test-runner');

assert.strictEqual(createdItem.name, 'Controle de Acesso Baseado em Atributos (ABAC)');
assert(createdItem.files.length >= 1, 'Deve conter pelo menos o arquivo SECURITY.md');
console.log(`✅ Item criado com ID: ${createdItem.id} e slug: ${createdItem.slug}`);

// 5. Teste de Gestão Dinâmica de Tags
console.log('5. Testando addSecurityTag() e removeSecurityTag()...');
const withNewTag = addSecurityTag(createdItem.id, 'auditoria-estrita', 'test-runner');
assert(withNewTag.tags.includes('auditoria-estrita'), 'Tag "auditoria-estrita" deve ter sido adicionada');

const withRemovedTag = removeSecurityTag(createdItem.id, 'auditoria-estrita', 'test-runner');
assert(!withRemovedTag.tags.includes('auditoria-estrita'), 'Tag "auditoria-estrita" deve ter sido removida');
console.log('✅ Adição e remoção dinâmica de tags funcionando perfeitamente.');

// 6. Teste de Arquivos Técnicos
console.log('6. Testando saveSecurityFile(), listSecurityFiles() e getSecurityFile()...');
const saved = saveSecurityFile(createdItem.id, 'checklist.md', '# Checklist ABAC\n\n- [ ] Validar atributos no token\n- [ ] Registrar log de acesso', 'test-runner');
assert.strictEqual(saved.file.path, 'checklist.md');
assert(saved.file.sha256.length === 64, 'SHA-256 deve ter 64 caracteres');

const fileList = listSecurityFiles(createdItem.id);
assert(fileList.some(f => f.path === 'checklist.md'), 'checklist.md deve constar na listagem de arquivos');

const fetchedFile = getSecurityFile(createdItem.id, 'checklist.md');
assert.strictEqual(fetchedFile?.content, saved.file.content);
console.log('✅ Salvamento, leitura e integridade SHA-256 de arquivos verificados.');

// 7. Teste de Proteção ao SECURITY.md
console.log('7. Testando proteção de exclusão do SECURITY.md...');
assert.throws(() => deleteSecurityFile(createdItem.id, 'SECURITY.md', 'test-runner'), /não pode ser excluído/);
console.log('✅ Proteção contra exclusão acidental do SECURITY.md comprovada.');

// 8. Teste de Exclusão e Restauração de Arquivo Secundário
console.log('8. Testando deleteSecurityFile() e restoreSecurityFile()...');
deleteSecurityFile(createdItem.id, 'checklist.md', 'test-runner', false);
assert(getSecurityFile(createdItem.id, 'checklist.md') === null, 'Arquivo deletado não deve ser retornado por padrão');

const restored = restoreSecurityFile(createdItem.id, 'checklist.md', 'test-runner');
assert.strictEqual(restored.file.deletedAt, null, 'Arquivo restaurado não deve ter deletedAt');
console.log('✅ Soft-delete e restauração da lixeira funcionando com sucesso.');

// 9. Teste de Auditoria
console.log('9. Testando listSecurityAuditLogs()...');
const logs = listSecurityAuditLogs(createdItem.id);
assert(logs.length >= 3, `Deve conter histórico de auditoria completo, obtido ${logs.length}`);
console.log(`✅ Trilha de auditoria verificada com ${logs.length} eventos registrados.`);

// 10. Limpeza do Item de Teste
deleteSecurityItem(createdItem.id, 'test-runner', true);
console.log('✅ Item de teste removido após validação.');

console.log('🎉 TODOS OS 10 TESTES DE SEGURANÇA FORAM APROVADOS COM SUCESSO ABSOLUTO!');
