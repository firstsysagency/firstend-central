#!/usr/bin/env node
// ==============================================================================
// SCANNER DE SEGREDOS — CENTRAL DE CHAVES ZATTEN (CHECKLIST DE DEPLOY 294)
// Varre recursivamente arquivos para impedir vazamento de chaves no Git/Logs
// ==============================================================================

import fs from 'node:fs';
import path from 'node:path';

const SECRET_PATTERNS = [
  { name: 'Chave Zatten (API Key)', regex: /zat_[a-zA-Z0-9_-]{20,}/g },
  { name: 'Chave Stripe/Gateway', regex: /sk_(live|test)_[a-zA-Z0-9]{24,}/g },
  { name: 'GitHub Personal Token', regex: /gh[pousr]_[a-zA-Z0-9]{36,}/g },
  { name: 'Chave Privada PEM/RSA', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: 'Vault/OpenBao Root Token', regex: /s\.[a-zA-Z0-9]{24}/g },
  { name: 'URL com Senha em Texto Plano', regex: /postgres:\/\/[^:]+:[^@]+@[^/]+/g },
  { name: 'JSON Web Token (JWT)', regex: /eyJ[a-zA-Z0-9_-]{15,}\.eyJ[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}/g }
];

const IGNORED_PATHS = [
  'node_modules',
  'dist',
  '.git',
  '.tempmediaStorage',
  '.system_generated',
  'package-lock.json',
  'changes-logs.md',
  'scan-secrets.mjs',
  '.keys',
  '.env'
];

function scanDirectory(dir, findings = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (IGNORED_PATHS.some(ignored => fullPath.includes(ignored))) {
      continue;
    }

    if (entry.isDirectory()) {
      scanDirectory(fullPath, findings);
    } else if (entry.isFile()) {
      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        for (const pattern of SECRET_PATTERNS) {
          const matches = content.match(pattern.regex);
          if (matches) {
            findings.push({
              file: fullPath,
              pattern: pattern.name,
              count: matches.length
            });
          }
        }
      } catch {
        // Ignora arquivos binários
      }
    }
  }

  return findings;
}

console.log('🔍 [SECRET-SCANNER] Iniciando varredura de segredos no repositório...');
const targetDir = process.cwd();
const findings = scanDirectory(targetDir);

if (findings.length > 0) {
  console.error('\n❌ [ALERTA DE SEGURANÇA] Segredos detectados em arquivos do projeto:');
  for (const finding of findings) {
    console.error(`  - ${finding.file} (${finding.pattern}: ${finding.count} ocorrência(s))`);
  }
  console.error('\nRemova os segredos e utilize variáveis de ambiente no .env antes de commitar ou fazer deploy.');
  process.exit(1);
} else {
  console.log('✅ [SECRET-SCANNER] Nenhum segredo ou chave exposta encontrada. Repositório seguro para deploy!');
  process.exit(0);
}
