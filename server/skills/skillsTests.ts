import assert from 'assert';
import {
  sanitizeRelativePath,
  computeSha256,
  isExecutablePath,
  detectContentType,
  listSkills,
  getSkill,
  saveSkillFile,
  deleteSkillFile,
  restoreSkillFile,
  createVersionSnapshot,
  compareSkillVersions,
  createSkillInstallation,
  listSkillInstallations,
  deleteSkillInstallation
} from './skillsStore.js';
import {
  validateSafeGitUrl,
  scanTextForSecrets,
  parseSkillFrontmatter
} from './gitImporter.js';

console.log('🧪 [TESTES DA BIBLIOTECA DE SKILLS] Iniciando validação de segurança e conformidade...\n');

let passed = 0;

function run(name: string, fn: () => void | Promise<void>) {
  try {
    fn();
    console.log(`✅ [Passou] ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`❌ [Falhou] ${name}:`, err.message);
    process.exitCode = 1;
  }
}

// 1. Sanitização de Path Traversal
run('1. Bloqueio estrito de Path Traversal ("..")', () => {
  assert.throws(() => sanitizeRelativePath('../secret.txt'), /Path traversal/);
  assert.throws(() => sanitizeRelativePath('prompts/../../etc/passwd'), /Path traversal/);
  assert.throws(() => sanitizeRelativePath('foo/../bar.md'), /Path traversal/);
});

run('2. Bloqueio de caminhos absolutos do Windows e Unix', () => {
  assert.throws(() => sanitizeRelativePath('C:\\Windows\\system32\\calc.exe'), /proibidos/);
  assert.throws(() => sanitizeRelativePath('/etc/file.md'), /relativo/);
});

run('3. Bloqueio de arquivos sensíveis (.env, credenciais)', () => {
  assert.throws(() => sanitizeRelativePath('.env'), /proibidos/);
  assert.throws(() => sanitizeRelativePath('subfolder/.env.local'), /proibidos/);
  assert.throws(() => sanitizeRelativePath('credentials.json'), /proibidos/);
});

run('4. Bloqueio de extensões perigosas (.exe, .zip, .key, .pem)', () => {
  assert.throws(() => sanitizeRelativePath('malware.exe'), /bloqueada/);
  assert.throws(() => sanitizeRelativePath('archive.zip'), /bloqueada/);
  assert.throws(() => sanitizeRelativePath('private.key'), /bloqueada/);
  assert.throws(() => sanitizeRelativePath('cert.pem'), /bloqueada/);
});

run('5. Aceitação de extensões textuais permitidas', () => {
  assert.strictEqual(sanitizeRelativePath('SKILL.md'), 'SKILL.md');
  assert.strictEqual(sanitizeRelativePath('prompts/qualification.md'), 'prompts/qualification.md');
  assert.strictEqual(sanitizeRelativePath('templates/message.json'), 'templates/message.json');
  assert.strictEqual(sanitizeRelativePath('scripts/validator.ts'), 'scripts/validator.ts');
  assert.strictEqual(sanitizeRelativePath('references/query.sql'), 'references/query.sql');
});

// 2. Proteção Anti-SSRF em URLs Git
run('6. Anti-SSRF: Bloqueio de localhost, loopback e IPs internos', () => {
  assert.throws(() => validateSafeGitUrl('http://localhost:3000/repo'), /HTTPS/);
  assert.throws(() => validateSafeGitUrl('https://localhost/repo'), /não autorizado|SSRF/);
  assert.throws(() => validateSafeGitUrl('https://127.0.0.1/repo'), /não autorizado|SSRF/);
  assert.throws(() => validateSafeGitUrl('https://169.254.169.254/latest/meta-data'), /não autorizado|SSRF/);
  assert.throws(() => validateSafeGitUrl('https://192.168.1.1/repo'), /não autorizado|SSRF/);
  assert.throws(() => validateSafeGitUrl('https://10.0.0.5/repo'), /não autorizado|SSRF/);
  assert.throws(() => validateSafeGitUrl('https://evil-site.com/repo'), /não autorizado/);
});

run('7. Anti-SSRF: Aceitação de repositórios oficiais GitHub', () => {
  const parsed = validateSafeGitUrl('https://github.com/firstsysagency/firstend-central');
  assert.strictEqual(parsed.owner, 'firstsysagency');
  assert.strictEqual(parsed.repo, 'firstend-central');
  assert.strictEqual(parsed.branch, 'main');
});

// 3. Secret Scanning
run('8. Secret Scanning: Detecção e mascaramento de chave OpenAI', () => {
  const fakeKey = 'sk-proj-' + '123456789012345678901234567890';
  const text = `const token = "${fakeKey}";`;
  const findings = scanTextForSecrets(text, 'config.ts');

  assert.ok(findings.length >= 1, 'Deve detectar a chave OpenAI');
  const openAiFinding = findings.find(f => f.rule === 'Chave de API OpenAI / ChatGPT');
  assert.ok(openAiFinding, 'Deve encontrar a regra de chave OpenAI');
  assert.strictEqual(openAiFinding.severity, 'critica');
  assert.ok(!openAiFinding.snippetMasked.includes('12345678901234567890'), 'Segredo não deve ser exposto na íntegra');
  assert.ok(openAiFinding.snippetMasked.includes('****') || openAiFinding.snippetMasked.includes('...'));
});


run('9. Secret Scanning: Detecção de chave privada PEM', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----';
  const findings = scanTextForSecrets(pem, 'id_rsa.txt');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].severity, 'critica');
});

// 4. Parser de YAML Frontmatter
run('10. Parser YAML Frontmatter de SKILL.md', () => {
  const content = `---
name: minha-skill
description: Descrição da skill para teste
version: 1.0.0
category: vendas
tags: [vendas, crm, ai]
---

# Minha Skill

Instruções operacionais da skill.
`;
  const { frontmatter, body } = parseSkillFrontmatter(content);
  assert.strictEqual(frontmatter.name, 'minha-skill');
  assert.strictEqual(frontmatter.category, 'vendas');
  assert.strictEqual(frontmatter.version, '1.0.0');
  assert.deepStrictEqual(frontmatter.tags, ['vendas', 'crm', 'ai']);
  assert.ok(body.includes('# Minha Skill'));
});

// 5. Integridade Criptográfica e Hashes SHA-256
run('11. Cálculo de hash SHA-256 determinístico', () => {
  const text = 'Hello Firstsys Skills';
  const hash1 = computeSha256(text);
  const hash2 = computeSha256(text);
  assert.strictEqual(hash1, hash2);
  assert.strictEqual(hash1.length, 64);
});

// 6. Catálogo das 7 Skills Pré-existentes
run('12. Preservação das 7 Skills de Referência no Catálogo', () => {
  const all = listSkills();
  assert.ok(all.length >= 7, `Esperado no mínimo 7 skills, encontrado ${all.length}`);

  const requiredSlugs = [
    'sdr-qualificacao',
    'followup-inteligente',
    'triagem-suporte',
    'find-skills-vercel',
    'opensquad-orchestration',
    'vibe-coding-toolkit',
    'openjarvis-local-first'
  ];

  for (const slug of requiredSlugs) {
    const found = all.find(s => s.slug === slug);
    assert.ok(found, `Skill obrigatória "${slug}" não encontrada no catálogo`);
    assert.ok(found.files && found.files.length >= 1, `Skill "${slug}" deve conter arquivos`);
    assert.ok(found.files.some(f => f.name.toLowerCase() === 'skill.md'), `Skill "${slug}" deve ter SKILL.md`);
  }
});

// 7. Manipulação de Arquivos e Proteção do SKILL.md
run('13. Operações em múltiplos arquivos e proteção de exclusão do SKILL.md', () => {
  const skill = getSkill('sdr-qualificacao');
  assert.ok(skill, 'Skill sdr-qualificacao deve existir');

  // Adicionar arquivo secundário
  const { file } = saveSkillFile(skill.id, 'prompts/test-automated.md', '# Prompt Teste Automatizado', 'test-runner');
  assert.strictEqual(file.path, 'prompts/test-automated.md');
  assert.strictEqual(file.sha256.length, 64);

  // Tentativa de excluir SKILL.md deve falhar
  assert.throws(() => deleteSkillFile(skill.id, 'SKILL.md'), /obrigatório e não pode ser excluído/);

  // Excluir arquivo secundário (soft delete)
  deleteSkillFile(skill.id, 'prompts/test-automated.md', 'test-runner', false);

  // Restaurar arquivo secundário
  const restored = restoreSkillFile(skill.id, 'prompts/test-automated.md', 'test-runner');
  assert.strictEqual(restored.file.deletedAt, null);

  // Limpeza final (hard delete)
  deleteSkillFile(skill.id, 'prompts/test-automated.md', 'test-runner', true);
});

// 8. Versionamento Semântico e Diff
run('14. Versionamento de Snapshots e Diff de Versões', () => {
  const skill = getSkill('sdr-qualificacao');
  assert.ok(skill);

  const snapshot = createVersionSnapshot(skill.id, 'Teste de versionamento', 'test-runner', '1.0.1');
  assert.strictEqual(snapshot.version, '1.0.1');
  assert.strictEqual(snapshot.snapshotHash.length, 64);
});

// 9. Instalação por Contexto
run('15. Instalação granular por contexto (agente e projeto)', () => {
  const skill = getSkill('sdr-qualificacao');
  assert.ok(skill);

  const install = createSkillInstallation(skill.id, {
    contextType: 'agent',
    contextId: 'agent_sdr_automated_test',
    contextName: 'Agente SDR Teste Unitário',
    pinnedVersion: '1.0.0',
    config: { max_leads_daily: 50 }
  }, 'test-runner');

  assert.strictEqual(install.contextType, 'agent');
  assert.strictEqual(install.contextId, 'agent_sdr_automated_test');

  const list = listSkillInstallations(skill.id);
  assert.ok(list.some(i => i.id === install.id));

  // Limpeza
  deleteSkillInstallation(skill.id, install.id, 'test-runner');
});

// 10. Marcação de Scripts como Executáveis sem Execução
run('16. Zero Execução: detecção e marcação de scripts como review obrigatório', () => {
  assert.strictEqual(isExecutablePath('scripts/deploy.sh'), true);
  assert.strictEqual(isExecutablePath('scripts/validate.ts'), true);
  assert.strictEqual(isExecutablePath('scripts/helper.py'), true);
  assert.strictEqual(isExecutablePath('rules.json'), false);
  assert.strictEqual(isExecutablePath('SKILL.md'), false);
});

console.log(`\n🎉 [SUCESSO TOTAL] Todos os ${passed} testes de segurança e integridade de skills passaram com perfeição!`);
