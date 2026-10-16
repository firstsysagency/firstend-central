import fs from 'fs';
import path from 'path';
import { Skill, SkillFile, SkillVersion, SkillInstallation, SkillAuditLog } from './skillTypes.js';
import { computeSha256, isExecutablePath, detectContentType } from './skillsStore.js';

const DB_PATH = path.join(process.cwd(), 'server', 'db.json');

function buildSkillFile(skillId: string, relPath: string, content: string, origin: 'local' | 'git' = 'local'): SkillFile {
  const now = new Date().toISOString();
  const isExec = isExecutablePath(relPath);
  return {
    id: `file_${skillId.replace('skill_', '')}_${path.basename(relPath).replace(/[^a-zA-Z0-9]/g, '_')}`,
    skillId,
    path: relPath,
    name: path.basename(relPath),
    extension: path.extname(relPath),
    contentType: detectContentType(relPath),
    sizeBytes: Buffer.byteLength(content, 'utf8'),
    sha256: computeSha256(content),
    content,
    origin,
    isExecutable: isExec,
    requiresReview: isExec,
    version: '1.0.0',
    createdAt: now,
    updatedAt: now,
    deletedAt: null
  };
}

export function seedInitialSkills(): void {
  if (!fs.existsSync(DB_PATH)) return;

  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  if (!db.skills) db.skills = [];
  if (!db.skill_versions) db.skill_versions = [];
  if (!db.skill_installations) db.skill_installations = [];
  if (!db.skill_audit_logs) db.skill_audit_logs = [];

  const now = new Date().toISOString();

  // ============================================================================
  // 1. SDR & QUALIFICAÇÃO AUTOMATIZADA
  // ============================================================================
  let sdr = db.skills.find((s: any) => s.id === 'skill_sdr_qualificacao' || s.slug === 'sdr-qualificacao');
  const sdrFiles: SkillFile[] = [
    buildSkillFile('skill_sdr_qualificacao', 'SKILL.md', `---
name: sdr-qualificacao
description: Skill para conduzir conversas de qualificação de leads via WhatsApp, aplicando metodologia BANT e coletando dores e orçamento.
version: 1.0.0
category: vendas
author: Firstsys AI
license: Proprietária Firstsys
---

# Skill: Qualificação e SDR Automatizado

## Objetivo
Qualificar leads recebidos pelo WhatsApp identificando com precisão necessidade, autoridade, orçamento e timing (BANT), preparando a oportunidade para o time de vendas da Firstsys ou do CRM Zatten.

## Diretrizes de Comportamento
1. Faça perguntas curtas e empáticas (máximo 2 frases por mensagem).
2. Identifique o segmento do cliente e volume atual de atendimento.
3. Quando o lead atender aos critérios de qualificação, mova-o no Kanban para a coluna 'Qualificado' e atribua ao time comercial.
4. Caso o lead informe dados de contato ou empresa, salve nas propriedades customizadas correspondentes.

## Gatilhos de Notificação
- Quando o lead solicitar proposta ou reunião imediatamente, execute a ferramenta correspondente com título 'Lead Quente Solicitou Contato'.
`),
    buildSkillFile('skill_sdr_qualificacao', 'rules.json', JSON.stringify({
      max_questions_per_turn: 1,
      qualification_threshold_score: 75,
      auto_tag_qualified: true,
      tag_name: "sdr-qualificado",
      required_fields: ["segmento", "volume_mensal", "decisor_presente"]
    }, null, 2)),
    buildSkillFile('skill_sdr_qualificacao', 'prompts/qualification.md', `# Prompt: Condução de Qualificação BANT

Você é um SDR sênior consultivo da Firstsys. Seu tom é profissional, direto e amigável.
Evite saudações prolixas ou justificativas longas.

Fluxo de Sondagem:
1. "Tudo bem? Vi que você tem interesse na nossa solução. Hoje você busca automatizar vendas ou suporte?"
2. "Perfeito. Quantas conversas ou leads sua equipe atende por mês atualmente?"
3. "Entendido. Você mesmo quem define a contratação da ferramenta na empresa?"
`),
    buildSkillFile('skill_sdr_qualificacao', 'templates/message-template.md', `# Template de Encerramento de Qualificação Positiva

"Excelente, {{nome}}! Com base no seu volume de {{volume}} atendimentos, nossa tecnologia consegue economizar cerca de 70% do seu tempo manual. 
Vou passar seu contato para o nosso consultor especialista agendar uma demonstração rápida de 15 minutos com você ainda hoje. Qual o melhor horário?"
`)
  ];

  if (!sdr) {
    sdr = {
      id: 'skill_sdr_qualificacao',
      name: 'Qualificação e SDR Automatizado',
      slug: 'sdr-qualificacao',
      description: 'Skill para conduzir conversas de qualificação de leads via WhatsApp, aplicando metodologia BANT e coletando dores e orçamento.',
      category: 'vendas',
      tags: ['vendas', 'qualificacao', 'sdr', 'whatsapp', 'bant'],
      status: 'ativa',
      installed: true,
      version: '1.0.0',
      author: 'Firstsys AI',
      origin: 'propria',
      license: 'Proprietária Firstsys',
      riskLevel: 'baixo',
      securityWarnings: [],
      dependencies: [],
      permissions: ['zatten:read', 'zatten:write'],
      createdAt: now,
      updatedAt: now,
      files: sdrFiles
    };
    db.skills.push(sdr);
  } else {
    sdr.origin = sdr.origin || 'propria';
    sdr.license = sdr.license || 'Proprietária Firstsys';
    sdr.riskLevel = sdr.riskLevel || 'baixo';
    sdr.files = sdrFiles;
  }

  // ============================================================================
  // 2. FOLLOW-UP E REENGAJAMENTO INTELIGENTE
  // ============================================================================
  let followup = db.skills.find((s: any) => s.id === 'skill_followup_inteligente' || s.slug === 'followup-inteligente');
  const followupFiles: SkillFile[] = [
    buildSkillFile('skill_followup_inteligente', 'SKILL.md', `---
name: followup-inteligente
description: Cadência automatizada de reengajamento para contatos sem resposta recente, quebrando objeções comuns e resgatando oportunidades.
version: 1.1.0
category: atendimento
author: Firstsys AI
license: Proprietária Firstsys
---

# Skill: Follow-up e Reengajamento Inteligente

## Objetivo
Reconectar com leads e clientes que pararam de responder após o envio de apresentação ou proposta comercial.

## Estratégia de Cadência
- **D+1 (24 horas após envio):** Mensagem de cortesia perguntando se conseguiu visualizar o material.
- **D+3 (72 horas):** Envio de case de sucesso do mesmo nicho do lead.
- **D+7 (Última tentativa amigável):** Pergunta direta de fechamento ou encerramento temporário de contato.

## Instruções para a IA
- Sempre verifique o histórico antes de enviar nova mensagem.
- Respeite o tom humanizado e jamais envie mensagens robotizadas ou insistentes demais.
`),
    buildSkillFile('skill_followup_inteligente', 'config.json', JSON.stringify({
      cadence_days: [1, 3, 7],
      stop_on_reply: true,
      max_followup_attempts: 3,
      business_hours_only: true
    }, null, 2)),
    buildSkillFile('skill_followup_inteligente', 'prompts/reengagement.md', `# Prompt de Reengajamento Não Invasivo

Seja breve e nunca pareça cobrador. Use perguntas abertas focadas no interesse do lead:
- "Oi {{nome}}, conseguiu dar uma olhada na proposta que te enviei ontem?"
- "Passando só para compartilhar esse caso de um cliente que reduziu tempo de resposta em 85%."
`)
  ];

  if (!followup) {
    followup = {
      id: 'skill_followup_inteligente',
      name: 'Follow-up e Reengajamento Inteligente',
      slug: 'followup-inteligente',
      description: 'Cadência automatizada de reengajamento para contatos sem resposta recente, quebrando objeções comuns e resgatando oportunidades.',
      category: 'atendimento',
      tags: ['followup', 'reengajamento', 'crm', 'zatten'],
      status: 'ativa',
      installed: true,
      version: '1.1.0',
      author: 'Firstsys AI',
      origin: 'propria',
      license: 'Proprietária Firstsys',
      riskLevel: 'baixo',
      securityWarnings: [],
      dependencies: [],
      permissions: ['zatten:read', 'zatten:write'],
      createdAt: now,
      updatedAt: now,
      files: followupFiles
    };
    db.skills.push(followup);
  } else {
    followup.origin = followup.origin || 'propria';
    followup.license = followup.license || 'Proprietária Firstsys';
    followup.riskLevel = followup.riskLevel || 'baixo';
    followup.files = followupFiles;
  }

  // ============================================================================
  // 3. TRIAGEM E ROTEAMENTO DE SUPORTE
  // ============================================================================
  let suporte = db.skills.find((s: any) => s.id === 'skill_triagem_suporte' || s.slug === 'triagem-suporte');
  const suporteFiles: SkillFile[] = [
    buildSkillFile('skill_triagem_suporte', 'SKILL.md', `---
name: triagem-suporte
description: Identificação de solicitações técnicas, financeiras e contratuais, roteando para os departamentos corretos no CRM.
version: 1.0.0
category: suporte
author: Firstsys AI
license: Proprietária Firstsys
---

# Skill: Triagem e Roteamento de Suporte

## Objetivo
Detectar a natureza do chamado do cliente no WhatsApp e transferir para o time responsável com contexto estruturado.

## Mapeamento de Departamentos
- **Dúvidas de Cobrança / Boletos / NFs:** Atribuir ao Departamento Financeiro.
- **Problemas Técnicos e Bugs:** Coletar print ou descrição detalhada e atribuir ao Suporte Técnico Nível 2.
- **Renovação de Contrato / Upgrade:** Atribuir ao Comercial.
`),
    buildSkillFile('skill_triagem_suporte', 'rules.json', JSON.stringify({
      sentiment_analysis_enabled: true,
      escalate_urgency_words: ["urgente", "parou", "fora do ar", "processo", "reclame aqui", "cancelar"],
      auto_ticket_creation: true
    }, null, 2)),
    buildSkillFile('skill_triagem_suporte', 'references/department-routing.md', `# Matriz de Roteamento Departamental

| Tipo de Solicitação | Departamento Destino | Prioridade Padrão |
|----------------------|----------------------|-------------------|
| Boleto / 2ª via      | Financeiro           | Média             |
| Erro 500 / Sistema   | Suporte N2           | Alta              |
| Novo contrato        | Comercial            | Alta              |
| Dúvida de uso        | Atendimento N1       | Normal            |
`)
  ];

  if (!suporte) {
    suporte = {
      id: 'skill_triagem_suporte',
      name: 'Triagem e Roteamento de Suporte',
      slug: 'triagem-suporte',
      description: 'Identificação de solicitações técnicas, financeiras e contratuais, roteando para os departamentos corretos no CRM.',
      category: 'suporte',
      tags: ['suporte', 'triagem', 'departamentos', 'roteamento'],
      status: 'ativa',
      installed: false,
      version: '1.0.0',
      author: 'Firstsys AI',
      origin: 'propria',
      license: 'Proprietária Firstsys',
      riskLevel: 'baixo',
      securityWarnings: [],
      dependencies: [],
      permissions: ['zatten:read', 'zatten:write'],
      createdAt: now,
      updatedAt: now,
      files: suporteFiles
    };
    db.skills.push(suporte);
  } else {
    suporte.origin = suporte.origin || 'propria';
    suporte.license = suporte.license || 'Proprietária Firstsys';
    suporte.riskLevel = suporte.riskLevel || 'baixo';
    suporte.files = suporteFiles;
  }

  // ============================================================================
  // 4. FIND SKILLS - VERCEL
  // ============================================================================
  let findSkills = db.skills.find((s: any) => s.id === 'skill_find_skills_vercel' || s.slug === 'find-skills-vercel');
  const findSkillsFiles: SkillFile[] = [
    buildSkillFile('skill_find_skills_vercel', 'SKILL.md', `---
name: find-skills-vercel
description: Motor de descoberta semântica e busca de skills e plugins para ecossistemas modernos de IA e desenvolvimento web.
version: 1.2.0
category: engenharia
author: Vercel / Curadoria Firstsys
license: MIT
---

# Find Skills - Vercel Integration

## Visão Geral
Esta skill fornece capacidades de busca inteligente, recomendação de ferramentas baseadas no contexto de desenvolvimento de software e emparelhamento de plugins sob demanda.

## Casos de Uso
1. Identificar se uma determinada demanda já possui uma skill ou biblioteca testada.
2. Sugerir bibliotecas modernas mantidas e sem risco de segurança na cadeia de suprimentos.
`),
    buildSkillFile('skill_find_skills_vercel', 'README.md', `# Vercel Find Skills Reference

Inspirado no ecossistema Vercel AI SDK e repositórios abertos de skills para agentes.
Permite aos agentes localizar scripts de automação e templates reutilizáveis.
`),
    buildSkillFile('skill_find_skills_vercel', 'scripts/discovery.ts', `/**
 * Script de descoberta de skills (apenas leitura de metadados)
 * NOTA DE SEGURANÇA: Execução automática desabilitada. Tratado apenas como referência estruturada.
 */
export interface SkillSearchResult {
  slug: string;
  relevanceScore: number;
  tags: string[];
}
`),
    buildSkillFile('skill_find_skills_vercel', 'references/registry.json', JSON.stringify({
      curated_registries: [
        { name: "Firstsys Skills Library", url: "https://firstend.firstsys.com.br/skills" },
        { name: "Vercel AI SDK Catalog", url: "https://sdk.vercel.ai" }
      ]
    }, null, 2))
  ];

  if (!findSkills) {
    findSkills = {
      id: 'skill_find_skills_vercel',
      name: 'Find Skills - Vercel',
      slug: 'find-skills-vercel',
      description: 'Motor de descoberta semântica e busca de skills e plugins para ecossistemas modernos de IA e desenvolvimento web.',
      category: 'engenharia',
      tags: ['vercel', 'descoberta', 'plugins', 'engenharia', 'typescript'],
      status: 'ativa',
      installed: false,
      version: '1.2.0',
      author: 'Vercel / Curadoria Firstsys',
      origin: 'curada',
      license: 'MIT',
      repositoryUrl: 'https://github.com/vercel/ai',
      riskLevel: 'baixo',
      securityWarnings: ['Contém referências de código TypeScript mantidas sob licença aberta MIT.'],
      dependencies: ['@vercel/ai'],
      permissions: ['fs:read'],
      createdAt: now,
      updatedAt: now,
      files: findSkillsFiles
    };
    db.skills.push(findSkills);
  } else {
    findSkills.files = findSkillsFiles;
  }

  // ============================================================================
  // 5. OPENSQUAD - ORQUESTRAÇÃO MULTIAGENTE
  // ============================================================================
  let openSquad = db.skills.find((s: any) => s.id === 'skill_opensquad_orchestration' || s.slug === 'opensquad-orchestration');
  const openSquadFiles: SkillFile[] = [
    buildSkillFile('skill_opensquad_orchestration', 'SKILL.md', `---
name: opensquad-orchestration
description: Padrões de decomposição de tarefas complexas entre múltiplos agentes especializados com handoff explícito e supervisão central.
version: 2.0.0
category: orquestracao
author: OpenSquad Community / Firstsys
license: Apache-2.0
---

# OpenSquad: Orquestração Multiagente

## Princípios Arquiteturais
- **Divisão de Responsabilidades:** Cada agente tem apenas uma persona e responsabilidade bem delimitada (ex: Pesquisador, Redator, Auditor, Executor).
- **Handoff Transparente:** O repasse de contexto entre agentes é feito via payloads JSON imutáveis com histórico de decisões.
- **Supervisão do Orquestrador:** Um agente líder avalia a qualidade da entrega antes de retornar a resposta final ao usuário.
`),
    buildSkillFile('skill_opensquad_orchestration', 'README.md', `# OpenSquad Architecture Guide

Arquitetura distribuída para agentes que colaboram em squads temáticos:
- Squad de Vendas (SDR + Closer + Onboarding)
- Squad de Engenharia (Coder + Reviewer + QA Tester)
- Squad de Suporte (Triador + Nível 2 + Financeiro)
`),
    buildSkillFile('skill_opensquad_orchestration', 'config.json', JSON.stringify({
      max_handoff_turns: 5,
      enable_consensus_voting: false,
      timeout_seconds_per_agent: 30
    }, null, 2)),
    buildSkillFile('skill_opensquad_orchestration', 'prompts/agent-router.md', `# Prompt: Roteador de Tarefas Multiagente

Você é o Orquestrador Central. Ao receber um objetivo do usuário:
1. Decomponha a solicitação em até 3 subtarefas sequenciais.
2. Indique qual subagente deve executar cada etapa.
3. Não invente saídas parciais; delegue e consolide.
`)
  ];

  if (!openSquad) {
    openSquad = {
      id: 'skill_opensquad_orchestration',
      name: 'OpenSquad - Orquestração Multiagente',
      slug: 'opensquad-orchestration',
      description: 'Padrões de decomposição de tarefas complexas entre agentes especializados com handoff explícito e supervisão central.',
      category: 'orquestracao',
      tags: ['orquestracao', 'multiagente', 'handoff', 'squads', 'arquitetura'],
      status: 'ativa',
      installed: false,
      version: '2.0.0',
      author: 'OpenSquad Community / Firstsys',
      origin: 'curada',
      license: 'Apache-2.0',
      repositoryUrl: 'https://github.com/opensquad/opensquad',
      riskLevel: 'baixo',
      securityWarnings: [],
      dependencies: [],
      permissions: ['net:http', 'agent:delegate'],
      createdAt: now,
      updatedAt: now,
      files: openSquadFiles
    };
    db.skills.push(openSquad);
  } else {
    openSquad.files = openSquadFiles;
  }

  // ============================================================================
  // 6. VIBE CODING TOOLKIT - ENGENHARIA E QUALITY GATES
  // ============================================================================
  let vibeCoding = db.skills.find((s: any) => s.id === 'skill_vibe_coding_toolkit' || s.slug === 'vibe-coding-toolkit');
  const vibeCodingFiles: SkillFile[] = [
    buildSkillFile('skill_vibe_coding_toolkit', 'SKILL.md', `---
name: vibe-coding-toolkit
description: Conjunto de boas práticas de desenvolvimento ágil assistido por IA, validação contínua de tipos, testes e prevenção de código duplicado.
version: 1.0.0
category: engenharia
author: Firstsys Dev Core
license: MIT
---

# Vibe Coding Toolkit: Engenharia e Quality Gates

## Diretrizes de Qualidade
1. **Inspeção Prévia (Look Before You Leap):** Nunca presuma a ausência de um arquivo. Inspecione sempre antes de criar ou modificar.
2. **Edição Cirúrgica:** Nunca sobrescreva um arquivo inteiro quando edições pontuais bastam.
3. **Typecheck Contínuo:** Valide com o compilador TypeScript antes de declarar uma tarefa concluída.
4. **Prevenção de Código Duplicado:** Reutilize módulos e componentes existentes.
`),
    buildSkillFile('skill_vibe_coding_toolkit', 'rules.json', JSON.stringify({
      enforce_strict_types: true,
      max_function_lines: 60,
      require_unit_tests: true,
      prohibit_full_file_rewrites: true
    }, null, 2)),
    buildSkillFile('skill_vibe_coding_toolkit', 'scripts/quality-gate.ts', `/**
 * Quality Gate Linter Rules
 * Exemplo de especificação de regras estáticas de engenharia Firstsys.
 */
export const QUALITY_STANDARDS = {
  zeroAnyTypes: true,
  explicitReturnType: true,
  noDeadCode: true
};
`),
    buildSkillFile('skill_vibe_coding_toolkit', 'references/best-practices.md', `# Boas Práticas de Engenharia Firstsys

- **Frontend:** React 19, TypeScript estrito, Framer Motion a 60 FPS estáveis, Tailwind CSS v4.
- **Backend:** Node.js ESM, Express, Schemas Zod, Hash SHA-256 para integridade.
- **Segurança:** Zod strict, sanitização de caminhos (anti-traversal), zero secrets no cliente.
`)
  ];

  if (!vibeCoding) {
    vibeCoding = {
      id: 'skill_vibe_coding_toolkit',
      name: 'Vibe Coding Toolkit - Engenharia e Quality Gates',
      slug: 'vibe-coding-toolkit',
      description: 'Conjunto de boas práticas de desenvolvimento ágil assistido por IA, validação contínua de tipos, testes e prevenção de código duplicado.',
      category: 'engenharia',
      tags: ['engenharia', 'quality-gate', 'typescript', 'clean-code', 'seguranca'],
      status: 'ativa',
      installed: false,
      version: '1.0.0',
      author: 'Firstsys Dev Core',
      origin: 'curada',
      license: 'MIT',
      riskLevel: 'baixo',
      securityWarnings: [],
      dependencies: ['typescript', 'oxlint'],
      permissions: ['fs:read'],
      createdAt: now,
      updatedAt: now,
      files: vibeCodingFiles
    };
    db.skills.push(vibeCoding);
  } else {
    vibeCoding.files = vibeCodingFiles;
  }

  // ============================================================================
  // 7. OPENJARVIS - AGENTES LOCAL-FIRST
  // ============================================================================
  let openJarvis = db.skills.find((s: any) => s.id === 'skill_openjarvis_local_first' || s.slug === 'openjarvis-local-first');
  const openJarvisFiles: SkillFile[] = [
    buildSkillFile('skill_openjarvis_local_first', 'SKILL.md', `---
name: openjarvis-local-first
description: Arquitetura local-first para execução de tarefas autônomas com privacidade de dados e failover resiliente.
version: 1.0.0
category: automacao
author: Jarvis Community / Curadoria Firstsys
license: MIT
---

# OpenJarvis: Agentes Local-First

## Visão Geral
Habilita agentes autônomos que priorizam a execução em nós locais ou em infraestrutura privada (VPS Firstsys), garantindo que dados confidenciais e credenciais nunca trafeguem por serviços externos desnecessários.

## Pilares
1. **Privacidade Absoluta:** Vetores e dados em repouso cifrados.
2. **Resiliência Offline:** Suporte a cache local com failover gracioso.
3. **Auditoria Criptográfica:** Toda transação assina um log SHA-256.
`),
    buildSkillFile('skill_openjarvis_local_first', 'README.md', `# OpenJarvis Protocol Specifications

Padrões de comunicação via MCP (Model Context Protocol) e JSON-RPC local.
`),
    buildSkillFile('skill_openjarvis_local_first', 'config.json', JSON.stringify({
      local_storage_path: "./storage/local-first",
      encryption_cipher: "aes-256-gcm",
      allow_cloud_fallback: false
    }, null, 2)),
    buildSkillFile('skill_openjarvis_local_first', 'references/local-protocols.md', `# Protocolos de Comunicação Local

1. Chamadas locais autenticadas via Bearer Token e HMAC SHA-256.
2. Persistência em arquivo JSON estruturado atômico com .tmp swap.
`)
  ];

  if (!openJarvis) {
    openJarvis = {
      id: 'skill_openjarvis_local_first',
      name: 'OpenJarvis - Agentes Local-First',
      slug: 'openjarvis-local-first',
      description: 'Arquitetura local-first para execução de tarefas autônomas com privacidade de dados e failover resiliente.',
      category: 'automacao',
      tags: ['local-first', 'privacidade', 'mcp', 'automacao', 'resiliencia'],
      status: 'ativa',
      installed: false,
      version: '1.0.0',
      author: 'Jarvis Community / Curadoria Firstsys',
      origin: 'curada',
      license: 'MIT',
      repositoryUrl: 'https://github.com/openjarvis/openjarvis',
      riskLevel: 'baixo',
      securityWarnings: [],
      dependencies: [],
      permissions: ['fs:read', 'fs:write'],
      createdAt: now,
      updatedAt: now,
      files: openJarvisFiles
    };
    db.skills.push(openJarvis);
  } else {
    openJarvis.files = openJarvisFiles;
  }

  // Garantir que cada uma das 7 skills tenha ao menos um snapshot de versão cadastrado
  for (const s of db.skills) {
    const existingVer = db.skill_versions.find((v: any) => v.skillId === s.id);
    if (!existingVer && s.files) {
      const filesSnapshot = s.files.map((f: any) => ({
        path: f.path,
        sha256: f.sha256 || computeSha256(f.content || ''),
        sizeBytes: f.sizeBytes || Buffer.byteLength(f.content || '', 'utf8'),
        name: f.name
      }));
      const sortedHashes = filesSnapshot.map((f: any) => `${f.path}:${f.sha256}`).sort().join('|');
      db.skill_versions.push({
        id: `ver_${s.id.replace('skill_', '')}_init`,
        skillId: s.id,
        version: s.version || '1.0.0',
        changelog: 'Snapshot inicial da biblioteca corporativa de skills',
        snapshotHash: computeSha256(sortedHashes),
        filesSnapshot,
        createdAt: now,
        createdBy: 'Firstsys System'
      });
    }
  }

  // Criar instalações padrão de exemplo caso a lista esteja vazia
  if (db.skill_installations.length === 0) {
    db.skill_installations.push({
      id: 'inst_sdr_conn_coolify',
      skillId: 'skill_sdr_qualificacao',
      contextType: 'connection',
      contextId: 'conn_coolify_principal',
      contextName: 'Zatten Produção (Coolify)',
      pinnedVersion: '1.0.0',
      status: 'active',
      config: { auto_reply: true, max_response_delay_sec: 5 },
      grantedPermissions: ['zatten:read', 'zatten:write'],
      installedAt: now,
      installedBy: 'Lucas Santos'
    });
    db.skill_installations.push({
      id: 'inst_followup_conn_coolify',
      skillId: 'skill_followup_inteligente',
      contextType: 'connection',
      contextId: 'conn_coolify_principal',
      contextName: 'Zatten Produção (Coolify)',
      pinnedVersion: '1.1.0',
      status: 'active',
      config: { cadence_interval_hours: 24 },
      grantedPermissions: ['zatten:read', 'zatten:write'],
      installedAt: now,
      installedBy: 'Lucas Santos'
    });
  }

  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
  console.log('✅ Catálogo das 7 skills de referência migrado e inicializado com sucesso no db.json.');
}
