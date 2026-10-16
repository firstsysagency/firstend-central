import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { ZipArchive } = require('archiver');
import { generateOpenApiSpec } from '../server/oauth/oauthRoutes.js';
import { MCP_TOOLS_CATALOG } from '../server/mcp/mcpRouter.js';

const PROD_URL = 'https://firstend.firstsys.com.br';
const OUTPUT_DIR = path.resolve(process.cwd(), 'chatgpt-mcp-bundle');

// Limpa e recria diretório de saída
if (fs.existsSync(OUTPUT_DIR)) {
  fs.rmSync(OUTPUT_DIR, { recursive: true, force: true });
}
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

console.log('📦 Iniciando compilação do pacote MCP compatível com ChatGPT / Codex / Claude...');

// 1. OPENAPI.JSON COMPLETO
const openApiSpec = generateOpenApiSpec(PROD_URL);
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'openapi.json'),
  JSON.stringify(openApiSpec, null, 2),
  'utf8'
);
console.log(`✅ openapi.json gerado com ${Object.keys(openApiSpec.paths).length} ferramentas.`);

const PLUGIN_ID = 'plugin_asdk_app_6acb2a1e159c8191a53f5f2b3da33e8c';
const APP_ID = 'asdk_app_6acb2a1e159c8191a53f5f2b3da33e8c';
const DISPLAY_NAME = 'Firstsys MCP';

// 2. .MCP.JSON
const mcpJson = {
  mcpServers: {
    'firstsys-zatten': {
      url: `${PROD_URL}/mcp`,
      type: 'sse'
    }
  }
};
fs.writeFileSync(
  path.join(OUTPUT_DIR, '.mcp.json'),
  JSON.stringify(mcpJson, null, 2),
  'utf8'
);
console.log('✅ .mcp.json gerado.');

// 3. ESTRUTURA DE SKILLS INDIVIDUAIS (skills/*/SKILL.md)
const dbPath = path.resolve(process.cwd(), 'server', 'db.json');
let skillsList: any[] = [];
if (fs.existsSync(dbPath)) {
  try {
    const db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
    skillsList = db.skills || [];
  } catch (e) {
    console.error('Erro ao ler skills do db.json', e);
  }
}

const skillsBaseDir = path.join(OUTPUT_DIR, 'skills');
fs.mkdirSync(skillsBaseDir, { recursive: true });

function formatSkillMd(content: string, slug: string, desc: string): string {
  const cleaned = (content || '').replace(/^\uFEFF/, '').trim();
  const cleanDesc = (desc || '').replace(/[\r\n]+/g, ' ').replace(/"/g, '\\"').trim();

  const match = cleaned.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (match) {
    const body = match[2].trim();
    return `---\nname: ${slug}\ndescription: "${cleanDesc}"\n---\n\n${body}\n`;
  }

  return `---\nname: ${slug}\ndescription: "${cleanDesc}"\n---\n\n${cleaned}\n`;
}

for (const skill of skillsList) {
  const canonicalSlug = (skill.slug || skill.id || '')
    .toLowerCase()
    .replace(/^skill_/, '')
    .replace(/_/g, '-')
    .trim();

  if (!canonicalSlug) continue;

  const skillFolder = path.join(skillsBaseDir, canonicalSlug);
  fs.mkdirSync(skillFolder, { recursive: true });

  let hasSkillMd = false;

  for (const file of skill.files || []) {
    const fileName = file.name.startsWith('/') ? file.name.substring(1) : file.name;
    let fileContent = file.content || '';
    
    if (fileName.toLowerCase() === 'skill.md') {
      hasSkillMd = true;
      fileContent = formatSkillMd(fileContent, canonicalSlug, skill.description);
    }
    
    fs.writeFileSync(path.join(skillFolder, fileName), fileContent, 'utf8');
  }

  if (!hasSkillMd) {
    const defaultBody = `# Skill: ${skill.name}\n\n${skill.description || ''}\n`;
    const defaultContent = formatSkillMd(defaultBody, canonicalSlug, skill.description);
    fs.writeFileSync(path.join(skillFolder, 'SKILL.md'), defaultContent, 'utf8');
  }
}
console.log(`✅ Pasta skills/*/SKILL.md gerada com YAML frontmatter estrito para ${skillsList.length} skills.`);

// 4. INSTRUCTIONS.MD
const systemInstructions = `# Diretrizes Mestras do ChatGPT — Firstsys Zatten Central & Skills

Você é o assistente inteligente oficial integrado à Central de Operações Firstsys e ao CRM Zatten WhatsApp.
Seu objetivo é conduzir interações ágeis, seguras e orientadas a resultados no WhatsApp de ponta a ponta.

---

## 1. Identidade e Conexões
- **Servidor Remoto MCP:** \`${PROD_URL}/mcp\`
- **Modo de Autenticação:** OAuth 2.1 com tokens PKCE vinculados ao workspace da organização.
- **Segurança de Chaves:** Você NÃO tem acesso direto às chaves de API cruas (\`x-api-key\`). Todas as chamadas usam a \`connection_id\` do cliente autenticado e são intermediadas pelo backend seguro com cofre criptográfico AES-256-GCM.
- **Antes de Operar:** Se a \`connection_id\` não foi fornecida na mensagem, liste as conexões ativas com \`zatten_list_connections\` e utilize a principal.

---

## 2. Catálogo de Skills Especializadas
A Central conta com uma biblioteca de personas e procedimentos especializados.
- **Descobrir Skills:** Execute \`firstsys_skills_list\` para ver personas prontas.
- **Carregar Diretrizes da Skill:** Use \`firstsys_skills_get(skill_id)\` para ler as instruções detalhadas do arquivo \`SKILL.md\`.
`;
fs.writeFileSync(path.join(OUTPUT_DIR, 'instructions.md'), systemInstructions, 'utf8');
console.log('✅ instructions.md gerado.');

// 5. TOOLS_REFERENCE.MD
let toolsRef = `# Catálogo de Ferramentas MCP — Firstsys Zatten Central & Skills (Total: ${MCP_TOOLS_CATALOG.length} ferramentas)\n\n`;
for (const tool of MCP_TOOLS_CATALOG) {
  toolsRef += `### \`${tool.name}\`\n`;
  toolsRef += `- **Título:** ${tool.title || tool.name}\n`;
  toolsRef += `- **Descrição:** ${tool.description}\n\n`;
}
fs.writeFileSync(path.join(OUTPUT_DIR, 'tools_reference.md'), toolsRef, 'utf8');
console.log('✅ tools_reference.md gerado.');

// 6. README.MD
const readmeContent = `# Pacote Oficial MCP Firstsys Zatten Central & Skills

Este pacote reúne todas as especificações e instruções necessárias para conectar o **ChatGPT** ao servidor remoto MCP da **Central Firstsys** e ao CRM **Zatten WhatsApp**.

---

## Conteúdo do Pacote
1. \`.codex-plugin/plugin.json\`: Manifesto de Plugin OpenAI / Codex com bloco \`interface\` obrigatório.
2. \`.agent-plugin/plugin.json\`: Manifesto de Agente OpenAI.
3. \`.claude-plugin/plugin.json\`: Manifesto para Claude e clientes MCP.
4. \`.mcp.json\`: Configuração de servidor MCP remoto.
5. \`.app.json\`: Configuração de aplicativo OpenAI com vínculo ao \`asdk_app_6acb2a1e159c8191a53f5f2b3da33e8c\`.
6. \`skills/*/SKILL.md\`: Coleção de Skills e instruções operacionais da Central Firstsys com YAML frontmatter.
7. \`openapi.json\`: Especificação OpenAPI 3.1.0 completa das 40 ferramentas.
8. \`instructions.md\`: Prompt mestre de diretrizes operacionais.
9. \`tools_reference.md\`: Guia resumido de cada ferramenta disponível.
`;
fs.writeFileSync(path.join(OUTPUT_DIR, 'README.md'), readmeContent, 'utf8');
console.log('✅ README.md gerado.');

// FUNÇÃO AUXILIAR DE COMPACTAÇÃO VIA ARCHIVER
async function createBundleZip(sourceDir: string, outZipPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (fs.existsSync(outZipPath)) {
      fs.unlinkSync(outZipPath);
    }
    const output = fs.createWriteStream(outZipPath);
    const archive = new ZipArchive({
      zlib: { level: 9 },
      forceLocalTime: true
    });

    output.on('close', () => resolve());
    archive.on('error', (err: any) => reject(err));
    archive.pipe(output);
    archive.directory(sourceDir, false);
    archive.finalize();
  });
}

// DEFINIÇÃO DAS VARIANTES DE NOMENCLATURA PARA COBERTURA TOTAL DO VALIDADOR OPENAI
const VARIANTS = [
  {
    tag: 'display_name',
    name: DISPLAY_NAME, // "Firstsys MCP"
    zipFiles: ['firstsys-zatten-mcp-bundle.zip', 'Firstsys-MCP.zip']
  },
  {
    tag: 'app_id',
    name: APP_ID, // "asdk_app_6acb2a1e159c8191a53f5f2b3da33e8c"
    zipFiles: [`${APP_ID}.zip`]
  },
  {
    tag: 'plugin_id',
    name: PLUGIN_ID, // "plugin_asdk_app_6acb2a1e159c8191a53f5f2b3da33e8c"
    zipFiles: [`${PLUGIN_ID}.zip`]
  }
];

// Diretórios onde os arquivos ZIP finais devem ser disponibilizados
const DISTRIBUTION_DIRS = [
  path.resolve(process.cwd()),
  path.resolve(process.cwd(), 'public'),
  path.resolve(process.cwd(), '..'),
  path.resolve(process.cwd(), '..', 'non-deploy')
];

for (const variant of VARIANTS) {
  console.log(`\n⚙️ Compilando variante [${variant.tag}]: name = "${variant.name}"...`);

  // 1. .CODEX-PLUGIN/PLUGIN.JSON
  const codexPluginDir = path.join(OUTPUT_DIR, '.codex-plugin');
  fs.mkdirSync(codexPluginDir, { recursive: true });
  const codexPlugin = {
    schema_version: 'v1',
    name: variant.name,
    id: APP_ID,
    app_id: APP_ID,
    plugin_id: PLUGIN_ID,
    display_name: DISPLAY_NAME,
    version: '1.2.0',
    description: 'MCP da Firstsys — CRM Zatten WhatsApp & Skills de IA',
    interface: {
      displayName: DISPLAY_NAME,
      shortDescription: 'Conecte o ChatGPT ao CRM Zatten WhatsApp e execute Skills operacionais da Firstsys.',
      longDescription: 'Integração oficial da Central Firstsys com o CRM Zatten. Permite que o ChatGPT consulte dados cadastrais de leads, histórico de mensagens no WhatsApp, colunas do Kanban, atribuição de equipe com rodízio, envio de mensagens e templates HSM, disparo de automações e gerenciamento de Skills especializadas de IA.',
      developerName: 'Firstsys',
      category: 'Productivity',
      capabilities: ['Read', 'Write']
    },
    author: {
      name: 'Firstsys',
      email: 'contato@firstsys.com.br',
      url: PROD_URL
    },
    mcp: {
      server: `${PROD_URL}/mcp`,
      type: 'remote',
      sse_endpoint: `${PROD_URL}/mcp/sse`,
      messages_endpoint: `${PROD_URL}/mcp/messages`
    },
    api: {
      type: 'openapi',
      url: `${PROD_URL}/openapi.json`
    }
  };
  fs.writeFileSync(
    path.join(codexPluginDir, 'plugin.json'),
    JSON.stringify(codexPlugin, null, 2),
    'utf8'
  );

  // 2. .AGENT-PLUGIN/PLUGIN.JSON
  const agentPluginDir = path.join(OUTPUT_DIR, '.agent-plugin');
  fs.mkdirSync(agentPluginDir, { recursive: true });
  const agentPlugin = {
    schema_version: 'v1',
    name: variant.name,
    id: APP_ID,
    app_id: APP_ID,
    display_name: DISPLAY_NAME,
    version: '1.2.0',
    description: 'MCP da Firstsys — CRM Zatten WhatsApp & Skills de IA',
    interface: {
      displayName: DISPLAY_NAME,
      shortDescription: 'Conecte o ChatGPT ao CRM Zatten WhatsApp e execute Skills operacionais da Firstsys.',
      longDescription: 'Integração oficial da Central Firstsys com o CRM Zatten. Permite que o ChatGPT consulte dados cadastrais de leads, histórico de mensagens no WhatsApp, colunas do Kanban, atribuição de equipe com rodízio, envio de mensagens e templates HSM, disparo de automações e gerenciamento de Skills especializadas de IA.',
      developerName: 'Firstsys',
      category: 'Productivity',
      capabilities: ['Read', 'Write']
    },
    mcpServers: {
      'firstsys-zatten': {
        url: `${PROD_URL}/mcp`,
        type: 'remote'
      }
    }
  };
  fs.writeFileSync(
    path.join(agentPluginDir, 'plugin.json'),
    JSON.stringify(agentPlugin, null, 2),
    'utf8'
  );

  // 3. .CLAUDE-PLUGIN/PLUGIN.JSON
  const claudePluginDir = path.join(OUTPUT_DIR, '.claude-plugin');
  fs.mkdirSync(claudePluginDir, { recursive: true });
  const claudePlugin = {
    name: variant.name,
    display_name: DISPLAY_NAME,
    version: '1.2.0',
    description: 'MCP da Firstsys — CRM Zatten WhatsApp & Skills de IA',
    mcpServers: {
      'firstsys-zatten': {
        url: `${PROD_URL}/mcp`,
        type: 'sse'
      }
    }
  };
  fs.writeFileSync(
    path.join(claudePluginDir, 'plugin.json'),
    JSON.stringify(claudePlugin, null, 2),
    'utf8'
  );

  // 4. .APP.JSON
  const appJson = {
    id: APP_ID,
    name: variant.name,
    display_name: DISPLAY_NAME,
    version: '1.2.0',
    description: 'MCP da Firstsys — Gestão do CRM Zatten e Skills de Atendimento',
    apps: {
      'firstsys-zatten': {
        id: APP_ID,
        required: true
      }
    },
    interface: {
      displayName: DISPLAY_NAME,
      shortDescription: 'Conecte o ChatGPT ao CRM Zatten WhatsApp e execute Skills operacionais da Firstsys.',
      longDescription: 'Integração oficial da Central Firstsys com o CRM Zatten. Permite que o ChatGPT consulte dados cadastrais de leads, histórico de mensagens no WhatsApp, colunas do Kanban, atribuição de equipe com rodízio, envio de mensagens e templates HSM, disparo de automações e gerenciamento de Skills especializadas de IA.',
      developerName: 'Firstsys',
      category: 'Productivity',
      capabilities: ['Read', 'Write']
    },
    mcp: {
      url: `${PROD_URL}/mcp`
    },
    api: {
      type: 'openapi',
      url: `${PROD_URL}/openapi.json`
    }
  };
  fs.writeFileSync(
    path.join(OUTPUT_DIR, '.app.json'),
    JSON.stringify(appJson, null, 2),
    'utf8'
  );

  // 5. MCP-MANIFEST.JSON
  const mcpManifest = {
    schema_version: '2024-11-05',
    name: variant.name,
    title: DISPLAY_NAME,
    description: 'Servidor MCP remoto da Central Firstsys para integração do ChatGPT com o CRM Zatten WhatsApp e gestão de Skills de IA.',
    version: '1.2.0',
    homepage: PROD_URL,
    server: {
      type: 'remote',
      base_url: `${PROD_URL}/mcp`,
      sse_endpoint: `${PROD_URL}/mcp/sse`,
      messages_endpoint: `${PROD_URL}/mcp/messages`,
      tools_endpoint: `${PROD_URL}/mcp/tools/{toolName}`
    },
    authentication: {
      type: 'oauth2',
      issuer: PROD_URL,
      authorization_url: `${PROD_URL}/oauth/authorize`,
      token_url: `${PROD_URL}/oauth/token`,
      jwks_url: `${PROD_URL}/.well-known/jwks.json`,
      protected_resource_metadata: `${PROD_URL}/.well-known/oauth-protected-resource`,
      scopes_supported: [
        'profile',
        'connections:read',
        'zatten:read',
        'zatten:write',
        'zatten:messages'
      ]
    },
    tools_count: MCP_TOOLS_CATALOG.length,
    tools: MCP_TOOLS_CATALOG.map(t => ({
      name: t.name,
      title: t.title,
      description: t.description,
      tags: t.tags
    }))
  };
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'mcp-manifest.json'),
    JSON.stringify(mcpManifest, null, 2),
    'utf8'
  );

  // 6. AI-PLUGIN.JSON
  const aiPlugin = {
    schema_version: 'v1',
    name_for_human: DISPLAY_NAME,
    name_for_model: variant.name.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase(),
    description_for_human: 'Conecte seu ChatGPT ao CRM WhatsApp da Zatten para atender contatos, mover leads no kanban e acionar skills operacionais de IA.',
    description_for_model: 'Assistente oficial conectado à Central Firstsys e ao CRM Zatten.',
    auth: {
      type: 'oauth',
      client_url: `${PROD_URL}/oauth/authorize`,
      scope: 'profile connections:read zatten:read zatten:write zatten:messages',
      authorization_url: `${PROD_URL}/oauth/token`,
      verification_tokens: { openai: '' }
    },
    api: {
      type: 'openapi',
      url: `${PROD_URL}/openapi.json`,
      is_user_authenticated: true
    },
    logo_url: `${PROD_URL}/logo.png`,
    contact_email: 'contato@firstsys.com.br',
    legal_info_url: `${PROD_URL}/terms`
  };
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'ai-plugin.json'),
    JSON.stringify(aiPlugin, null, 2),
    'utf8'
  );

  // 7. ROOT SKILL.MD
  const rootSkillSlug = variant.name.replace(/[^a-zA-Z0-9_-]/g, '-').toLowerCase();
  const rootSkillMd = `---\nname: ${rootSkillSlug}\ndescription: "MCP da Firstsys — CRM Zatten WhatsApp e Coleção de Skills Operacionais de IA"\n---\n\n# ${DISPLAY_NAME}\n\nPacote oficial de ferramentas MCP e Skills operacionais para agentes de IA e ChatGPT.\n`;
  fs.writeFileSync(path.join(OUTPUT_DIR, 'SKILL.md'), rootSkillMd, 'utf8');

  // 8. GERAÇÃO DOS ARQUIVOS ZIP DESTA VARIANTE
  const tempZipPath = path.resolve(process.cwd(), `temp_${variant.tag}.zip`);
  await createBundleZip(OUTPUT_DIR, tempZipPath);
  console.log(`✅ ZIP temporário gerado (${fs.statSync(tempZipPath).size} bytes)`);

  for (const zipName of variant.zipFiles) {
    for (const dir of DISTRIBUTION_DIRS) {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const target = path.join(dir, zipName);
      fs.copyFileSync(tempZipPath, target);
      console.log(`📋 [${variant.tag}] Copiado -> ${target}`);
    }
  }

  if (fs.existsSync(tempZipPath)) fs.unlinkSync(tempZipPath);
}

console.log('\n🎉 TODAS AS VARIANTES DE PACOTE FORAM COMPILADAS COM SUCESSO TOTAL!');
