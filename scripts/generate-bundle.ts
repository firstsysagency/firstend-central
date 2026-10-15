import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
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

// 2. .CODEX-PLUGIN/PLUGIN.JSON (Exigido pelo validador da OpenAI)
const codexPluginDir = path.join(OUTPUT_DIR, '.codex-plugin');
fs.mkdirSync(codexPluginDir, { recursive: true });
const codexPlugin = {
  schema_version: 'v1',
  name: 'firstsys-mcp',
  display_name: 'Firstsys MCP',
  version: '1.2.0',
  description: 'MCP da Firstsys — CRM Zatten WhatsApp & Skills de IA',
  interface: {
    displayName: 'Firstsys MCP',
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
console.log('✅ .codex-plugin/plugin.json gerado com interface.');

// 3. .AGENT-PLUGIN/PLUGIN.JSON (Exigido pelo validador da OpenAI)
const agentPluginDir = path.join(OUTPUT_DIR, '.agent-plugin');
fs.mkdirSync(agentPluginDir, { recursive: true });
const agentPlugin = {
  schema_version: 'v1',
  name: 'firstsys-mcp',
  version: '1.2.0',
  description: 'MCP da Firstsys — CRM Zatten WhatsApp & Skills de IA',
  interface: {
    displayName: 'Firstsys MCP',
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
console.log('✅ .agent-plugin/plugin.json gerado.');

// 4. .CLAUDE-PLUGIN/PLUGIN.JSON (Exigido pelo validador da OpenAI)
const claudePluginDir = path.join(OUTPUT_DIR, '.claude-plugin');
fs.mkdirSync(claudePluginDir, { recursive: true });
const claudePlugin = {
  name: 'firstsys-mcp',
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
console.log('✅ .claude-plugin/plugin.json gerado.');

// 5. .MCP.JSON (Exigido pelo validador da OpenAI)
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

// 6. .APP.JSON (Exigido pelo validador da OpenAI)
const appJson = {
  name: 'Firstsys MCP',
  version: '1.2.0',
  description: 'MCP da Firstsys — Gestão do CRM Zatten e Skills de Atendimento',
  interface: {
    displayName: 'Firstsys MCP',
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
console.log('✅ .app.json gerado.');

// 7. ESTRUTURA DE SKILLS (skills/*/SKILL.md — Exigido pelo validador da OpenAI)
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

for (const skill of skillsList) {
  // Cria tanto por slug quanto por ID para máxima tolerância
  const slugsToCreate = [skill.slug, skill.id].filter(Boolean);
  
  for (const slug of slugsToCreate) {
    const skillFolder = path.join(skillsBaseDir, slug);
    fs.mkdirSync(skillFolder, { recursive: true });

    // Grava os arquivos da skill (SKILL.md, rules.json, etc.)
    for (const file of skill.files || []) {
      const fileName = file.name.startsWith('/') ? file.name.substring(1) : file.name;
      fs.writeFileSync(path.join(skillFolder, fileName), file.content || '', 'utf8');
    }

    // Se não tiver SKILL.md explícito, cria um padrão
    if (!fs.existsSync(path.join(skillFolder, 'SKILL.md'))) {
      fs.writeFileSync(
        path.join(skillFolder, 'SKILL.md'),
        `# Skill: ${skill.name}\n\n${skill.description}\n`,
        'utf8'
      );
    }
  }
}
console.log(`✅ Pasta skills/*/SKILL.md gerada com ${skillsList.length} skills da Central.`);

// 8. MCP-MANIFEST.JSON
const mcpManifest = {
  schema_version: '2024-11-05',
  name: 'firstsys-zatten-central',
  title: 'Firstsys Zatten Central & Skills MCP Server',
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
console.log('✅ mcp-manifest.json gerado.');

// 9. AI-PLUGIN.JSON (OpenAI Plugin / GPT Action)
const aiPlugin = {
  schema_version: 'v1',
  name_for_human: 'Firstsys Zatten Central & Skills',
  name_for_model: 'firstsys_zatten_central',
  description_for_human: 'Conecte seu ChatGPT ao CRM WhatsApp da Zatten para atender contatos, mover leads no kanban e acionar skills operacionais de IA.',
  description_for_model: 'Assistente oficial conectado à Central Firstsys e ao CRM Zatten. Permite consultar dados cadastrais de leads, histórico de mensagens, tags, propriedades personalizadas, colunas do kanban, atribuição de equipe, envio de mensagens e templates WhatsApp, disparo de automações, webhooks e gerenciamento dinâmico de Skills operacionais especializadas (firstsys_skills_*).',
  auth: {
    type: 'oauth',
    client_url: `${PROD_URL}/oauth/authorize`,
    scope: 'profile connections:read zatten:read zatten:write zatten:messages',
    authorization_url: `${PROD_URL}/oauth/token`,
    verification_tokens: {
      openai: ''
    }
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
console.log('✅ ai-plugin.json gerado.');

// 10. INSTRUCTIONS.MD (Prompt de Sistema Mestre para o Custom GPT)
const systemInstructions = `# Diretrizes Mestras do ChatGPT — Firstsys Zatten Central & Skills

Você é o assistente inteligente oficial integrado à Central de Operações Firstsys e ao CRM Zatten WhatsApp.
Seu objetivo é auxiliar a equipe comercial, de atendimento e pós-venda a gerenciar leads, qualificar oportunidades, conduzir automações e aplicar Skills especializadas.

---

## 1. Regras Fundamentais e Políticas de Segurança
1. **Identificação e Conexões:**
   - Ao iniciar qualquer conversa, se não souber a conexão Zatten ativa, chame \`zatten_list_connections\` para verificar as conexões disponíveis da organização.
2. **Formato de Números de Telefone:**
   - Sempre utilize o padrão internacional completo com DDI e DDD (somente dígitos) para o \`lead_number\` / \`leadNumber\` (ex: \`5511999999999\`).
3. **Confirmação Humana Obrigatória:**
   - A ferramenta \`zatten_send_message\` é uma ação de escrita sensível. Sempre exiba ao usuário o número do destinatário e o texto exato da mensagem, solicitando confirmação explícita antes de efetuar o envio.
4. **Proteção de Segredos e Templates:**
   - Ao consultar a configuração do agente (\`zatten_agent_config_get\`), jamais invente ou tente expor dados marcados com \`<redacted>\`.
   - Ao atualizar o agente (\`zatten_agent_config_update\`), sempre forneça \`expected_revision\`, \`reason\` e mantenha \`publish_agent: false\`.

---

## 2. Ecossistema de Skills de IA (\`firstsys_skills_*\`)
A Central conta com uma biblioteca de personas e procedimentos especializados.
- **Descobrir Habilidades:** Use \`firstsys_skills_list\` para saber quais skills estão cadastradas e se estão ativas (\`installed: true\`).
- **Carregar Diretrizes da Skill:** Use \`firstsys_skills_get(skill_id)\` para ler as instruções detalhadas do arquivo \`SKILL.md\` daquela persona. Ao carregar, adote imediatamente o tom de voz e as metodologias descritas no documento.
- **Ativar/Desativar:** Se o operador solicitar o uso de uma especialidade desativada, utilize \`firstsys_skills_install(skill_id, install=true)\`.
- **Criar ou Ajustar Skills:** Você pode criar novas personas com \`firstsys_skills_create\` ou ajustar diretrizes com \`firstsys_skills_update\`.

---

## 3. Fluxo Típico de Qualificação e Atendimento
1. **Consulta Cadastral:** Busque o lead via \`zatten_leads_leadnumber_get\`.
2. **Histórico de Conversas:** Se precisar de contexto anterior, chame \`zatten_messages_history_get(leadNumber, llm_format=true)\`.
3. **Propriedades e Tags:**
   - Consulte propriedades com \`zatten_properties_get\`.
   - Atualize campos qualificados (ex: faturamento, decisor, dor) com \`zatten_leads_leadnumber_properties_patch\`.
   - Aplique tags categorizadas com \`zatten_leads_leadnumber_tag_post\`.
4. **Kanban e Encaminhamento:**
   - Consulte etapas disponíveis com \`zatten_kanban_get\`.
   - Mova o lead para a coluna apropriada com \`zatten_leads_leadnumber_kanban_patch\`.
   - Descubra atendentes e departamentos com \`zatten_users_get\` ou \`zatten_attendants_list\`.
   - Atribua o responsável com \`zatten_leads_leadnumber_assignee_patch\`.
5. **Automações e Notificações:**
   - Para alertar o atendente no CRM, acione \`zatten_leads_leadnumber_notification_post\`.
   - Para disparar fluxos automatizados, acione \`zatten_flows_trigger_post\` ou \`zatten_automations_trigger_post\`.

---

## 4. Tom de Voz
- Seja preciso, cortês, analítico e profissional.
- Responda sempre em português do Brasil (pt-BR).
- Sintetize as informações do CRM de forma clara com bullet points, destacando status, tags e ações tomadas.
`;
fs.writeFileSync(path.join(OUTPUT_DIR, 'instructions.md'), systemInstructions, 'utf8');
console.log('✅ instructions.md gerado.');

// 11. TOOLS_REFERENCE.MD (Catálogo de Referência Rápida)
let toolsRef = `# Catálogo de Ferramentas MCP — Firstsys Zatten Central & Skills (Total: ${MCP_TOOLS_CATALOG.length} ferramentas)\n\n`;

const categories: Record<string, string[]> = {
  'Identidade & Conexões': ['firstsys_get_profile', 'zatten_list_connections', 'zatten_get_connection_status'],
  'CRM, Leads & Kanban': [
    'zatten_leads_leadnumber_get',
    'zatten_kanban_get',
    'zatten_leads_leadnumber_kanban_patch',
    'zatten_leads_leadnumber_notes_patch',
    'zatten_leads_leadnumber_properties_patch',
    'zatten_properties_get',
    'zatten_properties_slug_values_get',
    'zatten_tags_get',
    'zatten_leads_leadnumber_tag_post',
    'zatten_leads_leadnumber_tag_delete',
    'zatten_leads_leadnumber_threads_get',
    'zatten_update_lead'
  ],
  'Equipe & Atribuição': [
    'zatten_users_get',
    'zatten_attendants_list',
    'zatten_leads_leadnumber_assignee_patch',
    'zatten_leads_leadnumber_notification_post',
    'zatten_leads_leadnumber_toggle_attendant_response_post'
  ],
  'Mensagens & Templates WhatsApp': [
    'zatten_messages_text_post',
    'zatten_send_message',
    'zatten_messages_history_get',
    'zatten_templates_get',
    'zatten_templates_list',
    'zatten_messages_template_post',
    'zatten_messages_image_post',
    'zatten_messages_audio_post',
    'zatten_messages_video_post',
    'zatten_messages_file_post'
  ],
  'Automações, Flows & Agente': [
    'zatten_automations_trigger_post',
    'zatten_flows_trigger_post',
    'zatten_hooks_path_post',
    'zatten_agent_config_get',
    'zatten_agent_config_update'
  ],
  'Skills de IA': [
    'firstsys_skills_list',
    'firstsys_skills_get',
    'firstsys_skills_install',
    'firstsys_skills_create',
    'firstsys_skills_update',
    'firstsys_skills_delete'
  ]
};

for (const [catName, toolNames] of Object.entries(categories)) {
  toolsRef += `## ${catName}\n\n`;
  for (const name of toolNames) {
    const tool = MCP_TOOLS_CATALOG.find(t => t.name === name);
    if (!tool) continue;
    toolsRef += `### \`${tool.name}\`\n`;
    toolsRef += `- **Título:** ${tool.title || tool.name}\n`;
    toolsRef += `- **Descrição:** ${tool.description}\n`;
    const props = Object.keys(tool.inputSchema?.properties || {});
    if (props.length > 0) {
      toolsRef += `- **Parâmetros:** \`${props.join('`, `')}\`\n`;
    } else {
      toolsRef += `- **Parâmetros:** Nenhum (requisição sem corpo)\n`;
    }
    toolsRef += `\n`;
  }
}
fs.writeFileSync(path.join(OUTPUT_DIR, 'tools_reference.md'), toolsRef, 'utf8');
console.log('✅ tools_reference.md gerado.');

// 12. README.MD
const readmeContent = `# Pacote Oficial MCP Firstsys Zatten Central & Skills

Este pacote reúne todas as especificações e instruções necessárias para conectar o **ChatGPT** ao servidor remoto MCP da **Central Firstsys** e ao CRM **Zatten WhatsApp**.

---

## Conteúdo do Pacote
1. \`.codex-plugin/plugin.json\`: Manifesto de Plugin OpenAI / Codex.
2. \`.agent-plugin/plugin.json\`: Manifesto de Agente OpenAI.
3. \`.claude-plugin/plugin.json\`: Manifesto para Claude e clientes MCP.
4. \`.mcp.json\`: Configuração de servidor MCP remoto.
5. \`.app.json\`: Configuração de aplicativo OpenAI.
6. \`skills/*/SKILL.md\`: Coleção de Skills e instruções operacionais da Central Firstsys.
7. \`openapi.json\`: Especificação OpenAPI 3.1.0 completa das 40 ferramentas.
8. \`instructions.md\`: Prompt mestre de diretrizes operacionais.
9. \`tools_reference.md\`: Guia resumido de cada ferramenta disponível.

---

## Como Importar no ChatGPT (Plugins / Custom GPT)
1. No modal **Enviar nova versão** de Plugins do ChatGPT, selecione o arquivo **firstsys-zatten-mcp-bundle.zip**.
2. O validador da OpenAI detectará automaticamente os arquivos de plugin (\`.codex-plugin/plugin.json\`, \`.mcp.json\`, \`skills/*/SKILL.md\`) e aprovará a publicação.
`;
fs.writeFileSync(path.join(OUTPUT_DIR, 'README.md'), readmeContent, 'utf8');
console.log('✅ README.md gerado.');

// 13. COMPACTAÇÃO EM ARQUIVO .ZIP UNIVERSAL
const zipName = 'firstsys-zatten-mcp-bundle.zip';
const targetPaths = [
  path.resolve(process.cwd(), zipName),
  path.resolve(process.cwd(), 'public', zipName),
  path.resolve(process.cwd(), '..', zipName),
  path.resolve(process.cwd(), '..', 'non-deploy', zipName)
];

console.log('🤐 Compactando arquivos e pastas ocultas em .zip...');

// Criação de ZIP via tar.exe nativo (garante inclusão perfeita de pastas e arquivos ocultos como .codex-plugin, .mcp.json e skills/*/SKILL.md)
const tarCommand = `tar.exe -a -cf "${targetPaths[0]}" -C "${OUTPUT_DIR}" .`;

try {
  if (fs.existsSync(targetPaths[0])) {
    fs.unlinkSync(targetPaths[0]);
  }
  execSync(tarCommand, { stdio: 'inherit' });
  console.log(`✅ Arquivo ZIP criado com sucesso em: ${targetPaths[0]}`);

  // Copia para as pastas de distribuição
  for (let i = 1; i < targetPaths.length; i++) {
    const dest = targetPaths[i];
    const parent = path.dirname(dest);
    if (!fs.existsSync(parent)) fs.mkdirSync(parent, { recursive: true });
    fs.copyFileSync(targetPaths[0], dest);
    console.log(`📋 Copiado para: ${dest}`);
  }
} catch (err) {
  console.error('Erro ao compactar via tar.exe:', err);
}

console.log('🎉 PACOTE MCP DO CHATGPT COMPILADO COM SUCESSO TOTAL!');
