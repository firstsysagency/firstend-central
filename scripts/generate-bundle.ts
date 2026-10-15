import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { generateOpenApiSpec } from '../server/oauth/oauthRoutes.js';
import { MCP_TOOLS_CATALOG } from '../server/mcp/mcpRouter.js';

const PROD_URL = 'https://firstend.firstsys.com.br';
const OUTPUT_DIR = path.resolve(process.cwd(), 'chatgpt-mcp-bundle');

if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

console.log('📦 Iniciando compilação do pacote MCP para ChatGPT...');

// 1. OPENAPI.JSON COMPLETO
const openApiSpec = generateOpenApiSpec(PROD_URL);
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'openapi.json'),
  JSON.stringify(openApiSpec, null, 2),
  'utf8'
);
console.log(`✅ openapi.json gerado com ${Object.keys(openApiSpec.paths).length} ferramentas.`);

// 2. MCP-MANIFEST.JSON
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

// 3. AI-PLUGIN.JSON (OpenAI Plugin / GPT Action)
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

// 4. INSTRUCTIONS.MD (Prompt de Sistema Mestre para o Custom GPT)
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

// 5. TOOLS_REFERENCE.MD (Catálogo de Referência Rápida)
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

// 6. README.MD (Instruções de Importação no ChatGPT)
const readmeContent = `# Pacote Oficial MCP Firstsys Zatten Central & Skills

Este pacote reúne todas as especificações e instruções necessárias para conectar o **ChatGPT** ao servidor remoto MCP da **Central Firstsys** e ao CRM **Zatten WhatsApp**.

---

## Conteúdo do Pacote
1. \`openapi.json\`: Especificação OpenAPI 3.1.0 completa com todas as 40 ferramentas catalogadas e autenticação OAuth 2.1.
2. \`mcp-manifest.json\`: Manifesto de serviço MCP remoto padrão 2024-11-05.
3. \`ai-plugin.json\`: Manifesto de Action/Plugin da OpenAI.
4. \`instructions.md\`: Prompt mestre de diretrizes operacionais para colar nas instruções do Custom GPT.
5. \`tools_reference.md\`: Guia resumido de cada ferramenta disponível.

---

## Como Importar no ChatGPT (Custom GPT)

### Opção A: Importação Rápida via Arquivo ZIP
1. No ChatGPT, acesse **Explore GPTs** -> **Create a GPT** (ou configure um GPT existente).
2. Na aba **Configure**, no rodapé, clique em **Actions** -> **Create new action** (ou upload de arquivo de schema).
3. Se o ChatGPT solicitar upload do bundle, anexe este arquivo \`firstsys-zatten-mcp-bundle.zip\`.
4. Em **Authentication**, selecione **OAuth**:
   - **Client ID:** *(gerado na criação do cliente na Central ou fornecido pela Firstsys)*
   - **Client Secret:** *(fornecido pela Firstsys)*
   - **Authorization URL:** \`https://firstend.firstsys.com.br/oauth/authorize\`
   - **Token URL:** \`https://firstend.firstsys.com.br/oauth/token\`
   - **Scope:** \`profile connections:read zatten:read zatten:write zatten:messages\`
5. Na caixa de **Instructions** do GPT, copie e cole o texto do arquivo \`instructions.md\`.
6. Salve o GPT e teste a autenticação!

### Opção B: Importação Direta via URL
1. No campo **Schema**, importe a URL pública:
   \`\`\`
   https://firstend.firstsys.com.br/openapi.json
   \`\`\`
2. Configure a autenticação OAuth 2.1 conforme os links acima.
`;

fs.writeFileSync(path.join(OUTPUT_DIR, 'README.md'), readmeContent, 'utf8');
console.log('✅ README.md gerado.');

// 7. COMPACTAÇÃO EM ARQUIVO .ZIP UNIVERSAL
const zipName = 'firstsys-zatten-mcp-bundle.zip';
const targetPaths = [
  path.resolve(process.cwd(), zipName),
  path.resolve(process.cwd(), 'public', zipName),
  path.resolve(process.cwd(), '..', zipName),
  path.resolve(process.cwd(), '..', 'non-deploy', zipName)
];

console.log('🤐 Compactando arquivos em .zip...');

// Criação de ZIP via PowerShell nativo no Windows
const psCommand = `powershell -Command "Compress-Archive -Path '${OUTPUT_DIR}\\*' -DestinationPath '${targetPaths[0]}' -Force"`;
try {
  execSync(psCommand, { stdio: 'inherit' });
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
  console.error('Erro ao compactar via PowerShell:', err);
}

console.log('🎉 PACOTE MCP DO CHATGPT GERADO COM SUCESSO TOTAL!');
