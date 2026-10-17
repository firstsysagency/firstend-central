import path from 'path';
import crypto from 'crypto';
import {
  ALLOWED_TEXT_EXTENSIONS,
  BLOCKED_OR_SUSPICIOUS_EXTENSIONS,
  SENSITIVE_FILE_NAMES,
  MAX_FILE_SIZE_BYTES,
  GitImportPreviewResult,
  GitImportFileCandidate,
  GitScannedSecretFinding
} from './skillTypes.js';
import { computeSha256, isExecutablePath, detectContentType } from './skillsStore.js';

// ==============================================================================
// 1. REGRAS DE PREVENÇÃO CONTRA SSRF (SERVER-SIDE REQUEST FORGERY)
// ==============================================================================

const ALLOWED_GIT_HOSTS = [
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'gitlab.com'
];

export function validateSafeGitUrl(urlString: string): { owner: string; repo: string; branch: string; subpath?: string } {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlString.trim());
  } catch {
    throw new Error('URL inválida fornecida para importação Git.');
  }

  // 1. Validar protocolo (estritamente https)
  if (parsedUrl.protocol !== 'https:') {
    throw new Error('Apenas o protocolo seguro HTTPS é permitido para importação de repositórios Git.');
  }

  // 2. Validar hostname permitido
  const host = parsedUrl.hostname.toLowerCase();
  const isAllowedHost = ALLOWED_GIT_HOSTS.some(allowed => host === allowed || host.endsWith(`.${allowed}`));
  if (!isAllowedHost) {
    throw new Error(`Host "${host}" não autorizado. Apenas repositórios oficiais do GitHub e GitLab são suportados.`);
  }

  // 3. Bloqueio estrito de localhost, IPs internos e metadados de cloud
  const forbiddenPatterns = [
    'localhost', '127.', '0.0.0.0', '169.254.', '10.', '192.168.',
    '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
    '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.', '::1', 'metadata.google.internal'
  ];

  for (const pattern of forbiddenPatterns) {
    if (host.includes(pattern)) {
      throw new Error('Violação de segurança SSRF: Endereços de rede interna, loopback ou metadados são proibidos.');
    }
  }

  // 4. Bloqueio de portas não padrão
  if (parsedUrl.port && parsedUrl.port !== '443') {
    throw new Error('Porta não padrão proibida em conexões Git seguras.');
  }

  // 5. Extração segura de owner, repo, branch e subpath
  // Ex: https://github.com/vercel/ai/tree/main/examples/foo
  const segments = parsedUrl.pathname.replace(/^\/|\/$/g, '').split('/');
  if (segments.length < 2) {
    throw new Error('URL deve conter ao menos a organização/usuário e o nome do repositório (ex: https://github.com/owner/repo).');
  }

  const owner = segments[0];
  const repo = segments[1].replace(/\.git$/, '');

  let branch = 'main';
  let subpath: string | undefined;

  if (segments[2] === 'tree' && segments[3]) {
    branch = segments[3];
    if (segments.length > 4) {
      subpath = segments.slice(4).join('/');
    }
  }

  return { owner, repo, branch, subpath };
}

// ==============================================================================
// 2. SECRET SCANNING (DETECÇÃO DE CREDENCIAIS E SEGREDO EM TEXTO)
// ==============================================================================

const SECRET_PATTERNS: { rule: string; regex: RegExp; severity: 'alta' | 'critica' | 'media' }[] = [
  {
    rule: 'Chave de API OpenAI / ChatGPT',
    regex: /sk-[a-zA-Z0-9_\-]{20,}/g,
    severity: 'critica'
  },
  {
    rule: 'Chave Privada PEM (RSA/EC/DSA/OPENSSH)',
    regex: /-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----/g,
    severity: 'critica'
  },
  {
    rule: 'Token de Acesso GitHub',
    regex: /gh[pousr]_[a-zA-Z0-9]{36,}/g,
    severity: 'critica'
  },
  {
    rule: 'Chave de Produção Stripe',
    regex: /(?:sk|rk)_live_[a-zA-Z0-9]{24,}/g,
    severity: 'critica'
  },
  {
    rule: 'Credencial AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: 'alta'
  },
  {
    rule: 'Definição de Senha ou Secret em Configuração',
    regex: /(?:password|passwd|secret|api_key|apikey|access_token)\s*[:=]\s*["'][^"']{6,}["']/gi,
    severity: 'alta'
  }
];

function maskSecret(val: string): string {
  if (val.length <= 8) return '****';
  return `${val.substring(0, 4)}...${val.substring(val.length - 4)}`;
}

export function scanTextForSecrets(content: string, filePath: string): GitScannedSecretFinding[] {
  const findings: GitScannedSecretFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.regex.exec(line)) !== null) {
        findings.push({
          rule: pattern.rule,
          filePath,
          line: i + 1,
          snippetMasked: maskSecret(match[0]),
          severity: pattern.severity
        });
      }
    }
  }

  return findings;
}

// ==============================================================================
// 3. PARSER DE FRONTMATTER YAML DO SKILL.MD
// ==============================================================================

export interface SkillYamlFrontmatter {
  name?: string;
  description?: string;
  version?: string;
  category?: string;
  tags?: string[];
  author?: string;
  license?: string;
}

export function parseSkillFrontmatter(content: string): { frontmatter: SkillYamlFrontmatter; body: string } {
  const result: SkillYamlFrontmatter = {};
  if (!content.startsWith('---')) {
    return { frontmatter: result, body: content };
  }

  const endIndex = content.indexOf('\n---', 3);
  if (endIndex === -1) {
    return { frontmatter: result, body: content };
  }

  const rawYaml = content.substring(3, endIndex).trim();
  const body = content.substring(endIndex + 4).trim();

  const lines = rawYaml.split('\n');
  for (const line of lines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const key = line.substring(0, colonIndex).trim().toLowerCase();
      let val = line.substring(colonIndex + 1).trim();

      // Limpar aspas
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.substring(1, val.length - 1);
      }

      if (key === 'name') result.name = val;
      if (key === 'description') result.description = val;
      if (key === 'version') result.version = val;
      if (key === 'category') result.category = val;
      if (key === 'author') result.author = val;
      if (key === 'license') result.license = val;
      if (key === 'tags') {
        // Tratar tags inline [tag1, tag2] ou vírgula
        result.tags = val.replace(/[[\]]/g, '').split(',').map(t => t.trim()).filter(Boolean);
      }
    }
  }

  return { frontmatter: result, body };
}

// ==============================================================================
// 4. PREVIEW E FETCH DE REPOSITÓRIO GITHUB PÚBLICO
// ==============================================================================

interface GitHubTreeItem {
  path: string;
  mode: string;
  type: 'blob' | 'tree';
  sha: string;
  size?: number;
  url: string;
}

export async function previewGitRepository(repoUrl: string): Promise<GitImportPreviewResult> {
  const { owner, repo, branch, subpath } = validateSafeGitUrl(repoUrl);

  // Headers padrão de cliente seguro
  const headers: Record<string, string> = {
    'User-Agent': 'Firstsys-Skill-Importer/1.0',
    'Accept': 'application/vnd.github.v3+json'
  };

  // Se houver token de ambiente seguro para contornar rate limit do GitHub
  if (process.env.GITHUB_TOKEN) {
    headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
  }

  // 1. Obter informações do repositório (licença, descrição padrão, branch default)
  const repoMetaRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  if (!repoMetaRes.ok) {
    if (repoMetaRes.status === 404) {
      throw new Error(`Repositório "${owner}/${repo}" não encontrado ou é privado.`);
    }
    if (repoMetaRes.status === 403) {
      throw new Error('Limite de requisições públicas à API do GitHub atingido temporariamente. Tente novamente em alguns minutos.');
    }
    throw new Error(`Falha ao consultar metadados do repositório: HTTP ${repoMetaRes.status}`);
  }

  const repoMeta: any = await repoMetaRes.json();
  const defaultBranch = branch || repoMeta.default_branch || 'main';
  const licenseName = repoMeta.license?.spdx_id || repoMeta.license?.name || 'Não especificada';

  // 2. Obter árvore de arquivos recursiva via Git Tree API
  const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`;
  const treeRes = await fetch(treeUrl, { headers });
  if (!treeRes.ok) {
    throw new Error(`Não foi possível obter a árvore de arquivos do branch "${defaultBranch}".`);
  }

  const treeData: any = await treeRes.json();
  const rawItems: GitHubTreeItem[] = treeData.tree || [];

  // Filtrar blobs (arquivos) dentro do subpath se especificado
  const blobs = rawItems.filter(item => {
    if (item.type !== 'blob') return false;
    if (subpath) {
      return item.path.startsWith(`${subpath}/`) || item.path === subpath;
    }
    return true;
  });

  const candidates: GitImportFileCandidate[] = [];
  let ignoredCount = 0;
  let totalSizeBytes = 0;
  let skillMdContent: string | null = null;
  const securityFindings: GitScannedSecretFinding[] = [];
  const dependenciesDetected: Set<string> = new Set();

  for (const blob of blobs) {
    const rawPath = subpath ? blob.path.replace(new RegExp(`^${subpath}/`), '') : blob.path;
    const fileName = path.basename(rawPath).toLowerCase();
    const ext = path.extname(rawPath).toLowerCase();

    // Checar regras de arquivos proibidos ou ignorados
    let isIgnored = false;
    let ignoreReason: string | undefined;

    // Pastas de dependências e caches
    if (
      rawPath.includes('node_modules/') ||
      rawPath.includes('.git/') ||
      rawPath.includes('.venv/') ||
      rawPath.includes('venv/') ||
      rawPath.includes('__pycache__/') ||
      rawPath.includes('dist/') ||
      rawPath.includes('build/') ||
      rawPath.includes('.next/')
    ) {
      isIgnored = true;
      ignoreReason = 'Diretório de cache ou dependências compiladas';
    } else if (SENSITIVE_FILE_NAMES.includes(fileName as any)) {
      isIgnored = true;
      ignoreReason = 'Arquivo sensível ou credencial bloqueada';
    } else if (BLOCKED_OR_SUSPICIOUS_EXTENSIONS.includes(ext as any)) {
      isIgnored = true;
      ignoreReason = `Extensão potencialmente arriscada ou binária (${ext})`;
    } else if (!ALLOWED_TEXT_EXTENSIONS.includes(ext as any)) {
      isIgnored = true;
      ignoreReason = `Extensão não suportada no catálogo textual (${ext})`;
    } else if (blob.size && blob.size > MAX_FILE_SIZE_BYTES) {
      isIgnored = true;
      ignoreReason = `Tamanho (${Math.round((blob.size || 0) / 1024)} KB) excede o limite de 1 MB`;
    }

    if (isIgnored) {
      ignoredCount++;
    } else {
      totalSizeBytes += blob.size || 0;
    }

    const isExec = isExecutablePath(rawPath);

    candidates.push({
      path: rawPath,
      name: path.basename(rawPath),
      extension: ext,
      sizeBytes: blob.size || 0,
      isExecutable: isExec,
      isIgnored,
      ignoreReason,
      selected: !isIgnored
    });

    // Se for SKILL.md, fazer fetch do conteúdo inicial para extrair frontmatter
    if (!isIgnored && (rawPath.toLowerCase() === 'skill.md' || rawPath.toLowerCase().endsWith('/skill.md'))) {
      try {
        const rawContentRes = await fetch(
          `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${blob.path}`,
          { headers: { 'User-Agent': 'Firstsys-Skill-Importer/1.0' } }
        );
        if (rawContentRes.ok) {
          skillMdContent = await rawContentRes.text();
          // Realizar secret scanning no SKILL.md
          const secretsInSkillMd = scanTextForSecrets(skillMdContent, rawPath);
          securityFindings.push(...secretsInSkillMd);
        }
      } catch (err) {
        console.warn('Erro ao carregar SKILL.md para preview:', err);
      }
    }

    // Detecção de dependências via package.json ou requirements.txt
    if (fileName === 'package.json') {
      try {
        const pkgRes = await fetch(
          `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${blob.path}`,
          { headers: { 'User-Agent': 'Firstsys-Skill-Importer/1.0' } }
        );
        if (pkgRes.ok) {
          const pkgJson: any = await pkgRes.json();
          if (pkgJson.dependencies) {
            Object.keys(pkgJson.dependencies).slice(0, 15).forEach(dep => dependenciesDetected.add(dep));
          }
        }
      } catch {}
    }
  }

  // Parse do Frontmatter do SKILL.md se presente
  let detectedName = repoMeta.name;
  let detectedDescription = repoMeta.description || '';
  let detectedCategory = 'engenharia';
  let detectedTags: string[] = repoMeta.topics || [];

  if (skillMdContent) {
    const { frontmatter } = parseSkillFrontmatter(skillMdContent);
    if (frontmatter.name) detectedName = frontmatter.name;
    if (frontmatter.description) detectedDescription = frontmatter.description;
    if (frontmatter.category) detectedCategory = frontmatter.category;
    if (frontmatter.tags) detectedTags = Array.from(new Set([...detectedTags, ...frontmatter.tags]));
  }

  let riskLevel: 'baixo' | 'medio' | 'alto' = 'baixo';
  if (securityFindings.some(f => f.severity === 'critica')) {
    riskLevel = 'alto';
  } else if (securityFindings.length > 0 || candidates.some(c => c.isExecutable && !c.isIgnored)) {
    riskLevel = 'medio';
  }

  return {
    valid: true,
    repoUrl,
    owner,
    repo,
    branch: defaultBranch,
    commitSha: treeData.sha || 'latest',
    license: licenseName,
    detectedName,
    detectedDescription,
    detectedCategory,
    detectedTags,
    hasSkillMd: !!skillMdContent,
    files: candidates,
    ignoredCount,
    totalSizeBytes,
    securityFindings,
    dependenciesDetected: Array.from(dependenciesDetected),
    riskLevel,
    warningMessage: securityFindings.length > 0
      ? `Atenção: Foram detectados ${securityFindings.length} possíveis segredos ou credenciais em arquivos do repositório. Revise antes de importar.`
      : undefined
  };
}

// ==============================================================================
// 5. IMPORTAÇÃO REAL DOS ARQUIVOS SELECIONADOS DO REPOSITÓRIO GIT
// ==============================================================================

export async function fetchSelectedGitFiles(
  repoUrl: string,
  selectedPaths: string[]
): Promise<{ path: string; content: string; sha256: string; sizeBytes: number }[]> {
  const { owner, repo, branch, subpath } = validateSafeGitUrl(repoUrl);
  const importedFiles: { path: string; content: string; sha256: string; sizeBytes: number }[] = [];

  for (const relPath of selectedPaths) {
    const fullRemotePath = subpath ? `${subpath}/${relPath}` : relPath;
    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${fullRemotePath}`;

    const res = await fetch(rawUrl, {
      headers: { 'User-Agent': 'Firstsys-Skill-Importer/1.0' }
    });

    if (!res.ok) {
      console.warn(`Não foi possível baixar o arquivo "${relPath}" de ${rawUrl}: HTTP ${res.status}`);
      continue;
    }

    const content = await res.text();
    const sha256 = computeSha256(content);
    const sizeBytes = Buffer.byteLength(content, 'utf8');

    importedFiles.push({
      path: relPath,
      content,
      sha256,
      sizeBytes
    });
  }

  return importedFiles;
}
