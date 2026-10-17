import fs from 'fs';
import path from 'path';
import { Skill, SkillFile } from './skillTypes.js';
import { computeSha256, isExecutablePath, detectContentType } from './skillsStore.js';

const DB_PATH = path.join(process.cwd(), 'server', 'db.json');

function buildCreativeFile(skillId: string, relPath: string, content: string): SkillFile {
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
    origin: 'notion',
    isExecutable: isExec,
    requiresReview: isExec,
    version: '1.0.0',
    createdAt: now,
    updatedAt: now,
    deletedAt: null
  };
}

export function seedCreativeSkills(): void {
  if (!fs.existsSync(DB_PATH)) return;

  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  if (!db.skills) db.skills = [];
  if (!db.skill_versions) db.skill_versions = [];
  if (!db.skill_installations) db.skill_installations = [];
  if (!db.skill_audit_logs) db.skill_audit_logs = [];

  const now = new Date().toISOString();

  const CREATIVE_SKILLS: Array<{
    id: string;
    slug: string;
    name: string;
    description: string;
    category: string;
    tags: string[];
    riskLevel: 'baixo' | 'medio' | 'alto';
    permissions: string[];
    files: Array<{ path: string; content: string }>;
  }> = [
    // ==========================================================================
    // 1. PAPER-CUT MOTION
    // ==========================================================================
    {
      id: 'skill_paper_cut_motion',
      slug: 'paper-cut-motion',
      name: 'Paper-Cut Motion (Stop-Motion Paper Collage)',
      description: 'Criação de animações artesanais em stop-motion de papel recortado e colagem (Paper Collage), construindo cenas táteis peça por peça com sombras físicas e movimento a 12 FPS.',
      category: 'criativo',
      tags: ['motion-design', 'paper-cut', 'stop-motion', 'animacao', 'criativo', 'video', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: paper-cut-motion
description: Geração de animações stop-motion artesanais em papel recortado e colagem física.
version: 1.0.0
category: criativo
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# Paper-Cut Motion (Stop-Motion Paper Collage)

## Objetivo
Transformar conceitos abstratos, histórias de marcas e anúncios em animações stop-motion artesanais no estilo "paper collage" (colagem de papel recortado e rasgado), criando textura tátil e identidade visual inesquecível.

## Comando de Ativação
- \`/motion-design\`: Inicia a construção da cena stop-motion em papel recortado.

## Pipeline em 3 Prompts Encadeados

### 1. Definição da Cena e Paleta
- Escolha da textura base (papel kraft, cartolina texturizada, papel de jornal antigo, papel aquarela com fibras visíveis).
- Paleta de 4 a 5 cores contrastantes com saturação orgânica de tintas de serigrafia.

### 2. Decomposição em Camadas Físicas
- Cada elemento é descrito como um recorte individual de papel com:
  - Bordas rasgadas (\`torn paper edges\`) ou corte limpo de estilete (\`precise x-acto cut\`).
  - Sombra projetada de profundidade (\`drop shadow indicating layered paper depth\`).
  - Iluminação direcional quente com luz lateral que ressalta os relevos.

### 3. Prompt de Movimento (Runway Gen-3 / Kling / Midjourney)
- Configuração de framerate clássico de stop-motion: **12 FPS** (dois quadros por movimento).
- Substituição física sutil de peças entre frames (\`jitter\`, \`tactile stop-motion jitter\`).
- Instrução mestre:
  \`\`\`text
  A stop-motion paper cutout collage animation, crafted from textured colored paper layers with visible torn fiber edges. A handcrafted paper character moves through a multi-layered paper cut landscape, 12 fps stop motion jitter, directional warm studio side-lighting casting tangible paper drop shadows, tactile tactile artisan feel, 8k quality, cinematic depth.
  \`\`\`
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            target_fps: 12,
            aesthetic: "handcrafted_paper_collage",
            required_elements: ["visible_fibers", "layered_depth_shadows", "stop_motion_jitter"],
            prohibit_digital_smoothness: true
          }, null, 2)
        },
        {
          path: 'workflow.md',
          content: `# Workflow: Paper-Cut Motion
1. **Passo 1 (Conceituação):** Defina a mensagem da marca e o objeto central em papel.
2. **Passo 2 (Camadas):** Liste as 3 a 5 camadas de papel (fundo, meio, personagem/produto, primeiro plano).
3. **Passo 3 (Geração de Imagem):** Gere o quadro de referência estático via Midjourney v6.1.
4. **Passo 4 (Animação):** Transponha para gerador de vídeo (Runway Gen-3 / Kling) fixando a taxa de 12 FPS.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist de Qualidade: Paper-Cut
- [ ] As fibras e bordas rasgadas de papel estão visíveis?
- [ ] Há sombras de contato entre as camadas de papel?
- [ ] O movimento preserva o ritmo de stop-motion (sem interpolação digital excessiva)?
- [ ] A iluminação ressalta a profundidade do diorama?
`
        }
      ]
    },

    // ==========================================================================
    // 2. AD GENERATOR (40 PROVEN TEMPLATES)
    // ==========================================================================
    {
      id: 'skill_ad_generator',
      slug: 'ad-generator',
      name: 'Ad Generator (40 Proven Brand Templates)',
      description: 'Gerador automatizado de anúncios de alta conversão estruturados em 40 templates validados de grandes marcas globais, integrando foto do produto, identidade e copy persuasiva.',
      category: 'marketing',
      tags: ['ad-generator', 'anuncios', 'templates', 'copywriting', 'conversao', 'criativo', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: ad-generator
description: Geração sistemática de anúncios de alta conversão usando 40 templates comprovados de grandes marcas.
version: 1.0.0
category: marketing
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# Ad Generator (40 Proven Brand Templates)

## Objetivo
Estruturar rapidamente criativos publicitários para redes sociais (Instagram, TikTok, Meta Ads, Google Display) combinando fotos do produto com 40 frameworks de design comprovados de grandes marcas (Apple, Nike, Spotify, Glossier, Gymshark).

## Comando de Ativação
- \`/ad-generator\`: Inicia a consultoria e geração de criativos a partir de imagem do produto ou briefing de marca.

## Framework dos 40 Templates
Os templates cobrem as principais alavancas de conversão:
1. **Split Benefit:** Divisão meio a meio destacando o problema à esquerda e a solução à direita.
2. **Feature Teardown:** Linhas indicativas conectando benefícios específicos aos pontos da foto do produto.
3. **Social Proof Grid:** Depoimentos de 5 estrelas em cards flutuantes sobrepostos ao produto em uso.
4. **Bold Minimalist Typography:** Tipografia pesada de contraste com uma única frase de gancho e hero shot isolado.
5. **Before & After Real-Life:** Demonstração visual do impacto tangível com selo de garantia.
6. **Comparison Matrix:** Tabela comparativa clara "Nós vs Outros" com checks verdes e cruzes vermelhas.

## Regras de Composição Visual
- Proporção: Quadrado (1:1), Stories/Reels (9:16) ou Paisagem (16:9).
- Título principal limitado a no máximo 6 palavras de alto impacto.
- Botão ou indicação de Call to Action (CTA) em posição de leitura natural inferior.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            max_headline_words: 6,
            cta_button_contrast_ratio: 4.5,
            supported_formats: ["1:1", "9:16", "16:9"],
            required_brand_inputs: ["product_photo_url", "brand_colors", "unique_value_proposition"]
          }, null, 2)
        },
        {
          path: 'templates.json',
          content: JSON.stringify({
            categories: [
              {
                category_name: "Prova Social",
                templates: ["Review Carousel", "Customer Quote Overlay", "Star Rating Spotlight", "Influencer Badge"]
              },
              {
                category_name: "Benefício Direto",
                templates: ["Split Problem/Solution", "Ingredient Breakdown", "3-Step Result", "Stat Callout"]
              },
              {
                category_name: "Autoridade e Comparação",
                templates: ["Us vs Them Grid", "Awards Banner", "Scientific Backing Chart", "Founders Note"]
              }
            ]
          }, null, 2)
        },
        {
          path: 'checklist.md',
          content: `# Checklist do Criativo
- [ ] A proposta de valor é legível em menos de 3 segundos em tela de celular?
- [ ] O produto está nítido e em destaque com bom recorte de fundo?
- [ ] A hierarquia tipográfica guia o olho diretamente para a ação principal?
- [ ] A paleta de cores respeita o manual de identidade da marca?
`
        }
      ]
    },

    // ==========================================================================
    // 3. THE AD DIRECTOR
    // ==========================================================================
    {
      id: 'skill_the_ad_director',
      slug: 'the-ad-director',
      name: 'The Ad Director (Commercial Video Production)',
      description: 'Direção cinematográfica completa de filmes publicitários e comerciais em vídeo, estruturando kit de ativos de marca, roteiro cena a cena (Shot-by-Shot) e prompts de câmera e iluminação.',
      category: 'video',
      tags: ['ad-director', 'comerciais', 'video', 'direcao', 'roteiro', 'cinematografico', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: the-ad-director
description: Direção de arte e roteirização cinematográfica de comerciais de TV e anúncios de alta produção.
version: 1.0.0
category: video
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# The Ad Director (Commercial Video Production)

## Objetivo
Atuar como diretor sênior de comerciais de marca, orquestrando desde a concepção visual, moodboard e escolha de lentes até a entrega do roteiro técnico shot-by-shot com prompts prontos para geradores de vídeo de IA (Runway Gen-3, Kling, Sora).

## Comandos de Ativação
- \`/ad-assets\`: Gera o pacote estruturado de ativos (paleta cinematográfica, guia de figurino, cenários e tom de voz).
- \`/ad-director\`: Compõe o roteiro técnico shot-by-shot com enquadramentos, movimentos de câmera e prompts de geração.

## Estrutura de Cada Cena (Shot-by-Shot)
Para cada tomada do comercial, o Ad Director define:
1. **Shot Number & Duração:** Ex: Cena 02 - Duração: 3.5s.
2. **Visual & Ação:** O que acontece na frente da câmera em detalhes fotorrealistas.
3. **Câmera & Lente:** Distância focal (35mm, 50mm, 85mm anamórfica), movimento (dolly in suave, tracking shot, steadicam orbital).
4. **Iluminação & Cor:** Temperatura de cor (3200K tungstênio, 5600K luz do dia), estilo (chiaroscuro, golden hour, neon backlight).
5. **Áudio & Sound Design:** Efeitos sonoros (SFX), trilha sonora (estilo e BPM) e locução/narração.
6. **Prompt Mestre de IA:** Prompt em inglês refinado para injeção direta no motor de renderização de vídeo.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            default_aspect_ratio: "16:9",
            cinematic_frame_rate: "24fps",
            prohibit_amateur_motion: true,
            camera_moves_allowed: ["slow dolly in", "steadicam tracking", "crane tilt", "pan 45 degrees", "locked tripod with wind"]
          }, null, 2)
        },
        {
          path: 'workflow.md',
          content: `# Workflow: The Ad Director
1. **Passo 1 (/ad-assets):** Mapeamento do público, estilo visual do produto e referências cinematográficas.
2. **Passo 2:** Estruturação da curva dramática: Gancho (0-3s) -> Tensão/Desejo (3-15s) -> Revelação/Clímax (15-25s) -> CTA e Logo (25-30s).
3. **Passo 3 (/ad-director):** Escrita detalhada das tomadas 1 a N.
4. **Passo 4:** Exportação dos prompts mestres otimizados para Runway Gen-3 e Kling.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist do Diretor
- [ ] O primeiro shot captura a atenção em menos de 2 segundos?
- [ ] A continuidade de iluminação e figurino é mantida entre as cenas?
- [ ] Os prompts contêm descrições de lentes cinematográficas em vez de adjetivos genéricos?
- [ ] O áudio sugerido complementa o ritmo das transições visuais?
`
        }
      ]
    },

    // ==========================================================================
    // 4. PYNK AI UGC STUDIO
    // ==========================================================================
    {
      id: 'skill_pynk_ai_ugc_studio',
      slug: 'pynk-ai-ugc-studio',
      name: 'PYNK AI UGC Studio (15s Hyper-Realistic Ads)',
      description: 'Criação de anúncios em vídeo UGC de 15 segundos para redes sociais com influenciadores virtuais hiper-realistas, ganchos magnéticos e linguagem humana espontânea.',
      category: 'marketing',
      tags: ['ugc', 'influenciador', 'reviews', 'video-15s', 'social-media', 'criativo', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: pynk-ai-ugc-studio
description: Produção de vídeos de UGC hiper-realistas de 15 segundos com personagens virtuais autênticos.
version: 1.0.0
category: marketing
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# PYNK AI UGC Studio (15s Hyper-Realistic Ads)

## Objetivo
Gerar scripts e prompts completos para anúncios em formato UGC (User Generated Content) de 15 segundos no TikTok, Reels e Shorts, utilizando avatares e vozes de IA com espontaneidade, gírias leves, pausas de respiração e autenticidade de vídeo de smartphone.

## Comando de Ativação
- \`/ugc\`: Gera o roteiro de 15 segundos e a persona do criador de conteúdo.

## Estrutura do Roteiro de 15 Segundos
- **0 a 3s - O Gancho (Hook):** Quebra de padrão visual e verbal imediata. Ex: *"Se você ainda usa X em 2026, você tá perdendo tempo..."* ou *"Nem meu dermatologista acreditou nisso..."*.
- **3 a 8s - A Revelação do Problema e Teste:** Mostra o produto na mão com a câmera frontal do celular levemente instável e iluminação de janela.
- **8 a 12s - Prova e Sensação:** Textura, aplicação e resultado palpável na pele/tela/ambiente.
- **12 a 15s - CTA Natural:** Sem parecer vendedor agressivo: *"O link tá aqui embaixo antes que acabe o lote"*.

## Prompts para Câmera Frontal e Lip-Sync
- Enquadramento vertical \`9:16\`.
- Expressões faciais orgânicas (sobrancelha levantada, sorriso casual, pausas naturais com *"tipo assim"*).
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            target_duration_seconds: 15,
            aspect_ratio: "9:16",
            tone: "conversational_authentic_casual",
            prohibit_formal_corporate_speak: true,
            camera_style: "smartphone_handheld_front_camera"
          }, null, 2)
        },
        {
          path: 'workflow.md',
          content: `# Workflow: UGC de 15 Segundos
1. **Passo 1:** Escolha o arquétipo do criador (Estudante cansado, Especialista cético, Amiga sincera, Empreendedor acelerado).
2. **Passo 2:** Defina o gancho inicial com alta retenção.
3. **Passo 3:** Gere o script com marcações de pausas \`[pausa]\`, respiração e expressões \`[sorriso sutil]\`.
4. **Passo 4:** Gere os prompts de avatar para HeyGen / Kling / Hedra.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist de Autenticidade UGC
- [ ] O roteiro dura exatamente entre 13 e 15 segundos quando lido em ritmo normal?
- [ ] O tom soa como uma mensagem enviada a um amigo no WhatsApp?
- [ ] O produto aparece em cena antes do segundo 04?
- [ ] Há chamada clara para ação nos últimos 3 segundos?
`
        }
      ]
    },

    // ==========================================================================
    // 5. THE PROMPT DIRECTOR (CHARACTER-TO-VIDEO)
    // ==========================================================================
    {
      id: 'skill_the_prompt_director',
      slug: 'the-prompt-director',
      name: 'The Prompt Director (Character-to-Video Consistency)',
      description: 'Engenharia de prompts para consistência estrita de personagens entre múltiplos quadros e vídeos de IA, com character sheet de 6 ângulos e travamento facial.',
      category: 'imagem',
      tags: ['character-consistency', 'prompt-director', 'storyboard', 'cinematografia', 'midjourney-runway', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: the-prompt-director
description: Metodologia avançada para manter consistência absoluta de personagens em imagens e vídeos gerados por IA.
version: 1.0.0
category: imagem
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# The Prompt Director (Character-to-Video Consistency)

## Objetivo
Resolver o maior desafio da produção audiovisual com IA: manter o mesmo personagem com as mesmas feições, cabelo, roupas, proporções e estilo através de múltiplos planos, ângulos e transições para vídeo.

## Comandos de Ativação
- \`/image-prompter\`: Cria a matriz completa de consistência de imagem e a folha de personagem (Character Sheet).
- \`/video-prompter\`: Traduz as poses e ações estáticas em prompts de movimento para Runway Gen-3 e Kling preservando a identidade.

## A Folha de Personagem em 6 Ângulos (Character Sheet)
1. **Frontal:** Visão direta nos olhos com expressão neutra.
2. **Três Quartos Esquerda:** Visão em ângulo de 45 graus.
3. **Três Quartos Direita:** Ângulo oposto com a mesma luz.
4. **Perfil Lateral:** Alinhamento do nariz, queixo e linha da mandíbula.
5. **Costas / Silhueta:** Verificação de comprimento de cabelo e corte de roupa.
6. **Expressão Emocional:** Sorriso largo ou choque dramático.

## Âncoras Imutáveis de Prompt
- **Roupas:** Descrição física exata com cores HEX (ex: \`wearing a bespoke navy wool jacket #0A192F with brass buttons\`).
- **Olhos e Cabelo:** Descrição de tom, formato e estilo imutáveis.
- **Semente e Peso:** Travamento de sementes e referências com URLs de imagem (\`--sref\` e \`--cref\` no Midjourney).
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            required_sheet_angles: 6,
            require_hex_clothing_anchors: true,
            video_camera_damping: 0.7,
            prohibit_random_clothing_changes: true
          }, null, 2)
        },
        {
          path: 'workflow.md',
          content: `# Workflow: Consistência de Personagem
1. **Passo 1 (/image-prompter):** Defina o nome, idade, traços étnicos e roupas âncora do personagem.
2. **Passo 2:** Gere a Character Sheet em grid 3x2 no Midjourney usando \`character turnaround sheet\`.
3. **Passo 3:** Isole o quadro mestre e utilize como referência permanente (\`--cref\`).
4. **Passo 4 (/video-prompter):** Crie as ações de vídeo com transições suaves que não deformem o rosto.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist de Consistência
- [ ] O formato dos olhos e nariz permanece idêntico em todos os planos?
- [ ] A roupa não sofreu mutações mágicas entre tomadas?
- [ ] O movimento de vídeo preserva a estrutura óssea do rosto?
`
        }
      ]
    },

    // ==========================================================================
    // 6. VOX ANIMATIONS (EXPLAINER VIDEOS)
    // ==========================================================================
    {
      id: 'skill_vox_animations',
      slug: 'vox-animations',
      name: 'Vox Animations (Investigative Explainer Videos)',
      description: 'Roteirização e direção de arte para vídeos explicativos no estilo investigativo e visual do canal Vox, com mapas 3D animados, jornais recortados e gráficos dinâmicos.',
      category: 'video',
      tags: ['vox', 'explainer', 'motion-graphics', 'educativo', 'storytelling', 'animacao', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: vox-animations
description: Roteiro e direção de arte no formato dinâmico, investigativo e animado do canal Vox.
version: 1.0.0
category: video
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# Vox Animations (Investigative Explainer Videos)

## Objetivo
Criar vídeos educativos e jornalísticos de altíssimo engajamento no estilo dos canais Vox e Johnny Harris, combinando recortes de documentos históricos, mapas 3D com relevo topográfico, linhas de dados animadas e ritmo narrativo instigante.

## Comando de Ativação
- \`"let's make a video"\`: Inicia a estruturação completa do vídeo investigativo.

## Elementos de Linguagem Vox
1. **O Gancho de Curiosidade:** O vídeo sempre abre com uma anomalia ou pergunta contraintuitiva (*"Por que esse pequeno país no meio do Pacífico tem mais dinheiro que a Suíça?"*).
2. **Colagem Multimídia Ágil:** Mistura de arquivos confidenciais reais, fotografias antigas com recorte manual, caneta marca-texto amarela sublinhando trechos de jornais e gráficos minimalistas.
3. **Mapas Topográficos 3D:** Câmera que mergulha do espaço em ângulo inclinado sobre montanhas e fronteiras territoriais.
4. **Paleta Clássica Vox:** Fundo creme/papel (\`#F4F0EA\`), amarelo vibrante de destaque (\`#FFDE00\`) e preto editorial (\`#1A1A1A\`).
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            color_palette: {
              cream_paper: "#F4F0EA",
              vox_yellow: "#FFDE00",
              editorial_black: "#1A1A1A",
              alert_red: "#E63946"
            },
            narrative_structure: ["Anomaly Hook", "Context Collapse", "Data Investigation", "The Reveal", "Broader Implications"],
            camera_moves: ["satellite 3d tilt", "whip pan to document", "macro lens on newspaper fiber"]
          }, null, 2)
        },
        {
          path: 'workflow.md',
          content: `# Workflow: Vox Explainer
1. **Passo 1 (A Pergunta):** Formule a tese central investigativa.
2. **Passo 2 (Os Documentos):** Selecione os 3 a 5 dados ou gráficos comprobatórios.
3. **Passo 3 (Storyboard de Motion):** Alterne a cada 4 segundos entre narrador, mapa 3D e recorte de jornal.
4. **Passo 4 (Sound Design):** Inclua cliques de máquina de escrever, som de papel folheando e trilha de suspense suave.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist Vox
- [ ] Há um elemento visual mudando a cada 3 a 5 segundos?
- [ ] O mapa ou gráfico é imediatamente compreensível sem esforço?
- [ ] A marca-texto amarela guia a leitura no momento certo?
`
        }
      ]
    },

    // ==========================================================================
    // 7. STUDIO SHOT (CLEAN PACKSHOTS)
    // ==========================================================================
    {
      id: 'skill_studio_shot',
      slug: 'studio-shot',
      name: 'Studio Shot (Clean Packshots)',
      description: 'Transformação de fotos comuns de produtos em packshots de estúdio comercial de alto nível, com iluminação de 3 pontos, reflexos realistas e rótulos nítidos.',
      category: 'design',
      tags: ['packshot', 'produto', 'fotografia-estudio', 'ecommerce', 'iluminacao', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: studio-shot
description: Fotografias de estúdio profissional para e-commerce e catálogos com isolamento perfeito do produto.
version: 1.0.0
category: design
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# Studio Shot (Clean Packshots)

## Objetivo
Elevar fotos de celulares ou produtos brutos ao padrão de catálogos internacionais de marcas como Sephora, Apple e Aesop, com superfícies de estúdio impecáveis (mármore polido, concreto arquitetônico, acrílico fosco) e fidelidade aos materiais.

## Comando de Ativação
- \`/studio-shot\`: Transforma o briefing ou foto bruta em packshot de estúdio comercial.

## Esquemas de Iluminação Profissional
- **Key Light (Luz Principal):** Softbox difuso a 45 graus proporcionando iluminação suave sem estourar reflexos no produto.
- **Fill Light (Luz de Preenchimento):** Painel refletor branco suavizando as sombras laterais.
- **Rim Light (Luz de Borda):** Foco sutil atrás do produto destacando a linha de contorno contra o fundo.
- **Abertura e Foco:** Abertura \`f/8\` ou \`f/11\` para profundidade de campo total no produto com desfoque elegante apenas no fundo infinito.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            aperture_setting: "f/8 for complete product sharpness",
            lighting_setup: "3-point studio softbox setup",
            preserve_label_legibility: true,
            surfaces_available: ["polished white marble", "raw architectural concrete", "matte frosted acrylic", "dark slate", "natural oak wood"]
          }, null, 2)
        },
        {
          path: 'workflow.md',
          content: `# Workflow: Studio Packshot
1. **Passo 1:** Analise o material do produto (vidro translúcido, alumínio escovado, cerâmica fosca, papelão impresso).
2. **Passo 2:** Escolha a superfície de apoio que harmoniza com a paleta da embalagem.
3. **Passo 3:** Configure a iluminação de estúdio adequada para evitar reflexos indesejados.
4. **Passo 4:** Gere o prompt fotográfico técnico com detalhes de lente macro 100mm.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist do Packshot
- [ ] As letras do rótulo estão nítidas e legíveis?
- [ ] O material do frasco/embalagem parece autêntico ao toque?
- [ ] A sombra projetada na base tem gradiente suave e contato físico natural?
`
        }
      ]
    },

    // ==========================================================================
    // 8. PRODUCT VISUALS (LIFESTYLE & CINEMATIC)
    // ==========================================================================
    {
      id: 'skill_product_visuals',
      slug: 'product-visuals',
      name: 'Product Visuals (Lifestyle & Cinematic)',
      description: 'Inserção de produtos em cenários de estilo de vida cinematográficos, oferecendo modos Recreate (mesmo enquadramento/luz) e Recompose (leitura da cena).',
      category: 'design',
      tags: ['lifestyle', 'produto', 'cinematografico', 'recompose', 'recreate', 'campanhas', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: product-visuals
description: Ambientação de produtos em cenários cinematográficos de estilo de vida com os modos Recreate e Recompose.
version: 1.0.0
category: design
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# Product Visuals (Lifestyle & Cinematic)

## Objetivo
Inserir produtos em cenas de uso cotidiano de alto padrão (mesas de café iluminadas pelo sol da manhã, bancadas de banheiro de spa luxuoso, cabines de avião de primeira classe, caminhadas em florestas alpinas) mantendo o produto com integração de luz perfeita.

## Comando de Ativação
- \`/product-visuals\`: Inicia a ambientação do produto em cenários de estilo de vida.

## Modos Operacionais
1. **Modo Recreate:**
   - O usuário fornece uma foto de referência de campanha de outra marca com luz e composição desejadas.
   - A IA recria exatamente a mesma composição, profundidade de campo e iluminação, substituindo o objeto pelo produto do usuário.
2. **Modo Recompose:**
   - A IA analisa a proposta de valor do produto e propõe 3 novos cenários de narrativa visual onde o produto vive naturalmente.
   - Exemplo: um isotônico artesanal repousando sobre uma rocha úmida com névoa matinal e atletas ao fundo desfocados.
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            modes: ["recreate", "recompose"],
            ambient_light_bleed_integration: true,
            depth_of_field: "cinematic shallow bokeh f/2.8",
            prohibit_floating_objects: true
          }, null, 2)
        },
        {
          path: 'workflow.md',
          content: `# Workflow: Lifestyle Visuals
1. **Passo 1:** Escolha entre Recreate (copiar setup de foto de referência) ou Recompose (criar nova cena temática).
2. **Passo 2:** Defina a hora do dia (golden hour, meio-dia ensolarado, crepúsculo azul).
3. **Passo 3:** Ajuste a luz ambiente refletida no produto (\`ambient light bleed\`) para que a cor do ambiente banhe sutilmente as bordas do objeto.
4. **Passo 4:** Renderize com lente 50mm ou 85mm com desfoque de fundo suave.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist Lifestyle
- [ ] O produto parece verdadeiramente repousar sobre a superfície (sem parecer colado artificialmente)?
- [ ] A direção da luz solar ou artificial no ambiente é a mesma que atinge o produto?
- [ ] As pessoas ou elementos secundários de fundo não roubam o protagonismo do produto?
`
        }
      ]
    },

    // ==========================================================================
    // 9. CREATIVE FORMATS (5 DIFFERENTIATED LOOKS)
    // ==========================================================================
    {
      id: 'skill_creative_formats',
      slug: 'creative-formats',
      name: 'Creative Formats (5 Differentiated Looks)',
      description: 'Cinco formatos criativos disruptivos para anúncios de alto engajamento: Claymation (massinha), Animação de Papel, Videoclipe Musical, Objetos Falantes e Esqueletos Cômicos.',
      category: 'marketing',
      tags: ['claymation', 'talking-object', 'song-style-ad', 'skeleton-ads', 'criativo', 'viral', 'notion'],
      riskLevel: 'baixo',
      permissions: ['fs:read'],
      files: [
        {
          path: 'SKILL.md',
          content: `---
name: creative-formats
description: 5 formatos visuais disruptivos e virais para quebrar a cegueira de anúncios em redes sociais.
version: 1.0.0
category: marketing
author: Notion Claude Creative / Firstsys
origin: notion
license: Community Creative Commons
---

# Creative Formats (5 Differentiated Looks)

## Objetivo
Superar a fadiga de anúncios convencionais com 5 estilos visuais altamente memoráveis, divertidos e com alto poder de retenção em feeds do Instagram, TikTok e YouTube Shorts.

## Comandos dos 5 Formatos

### 1. \`/claymation\` - Animação de Massinha
- Estilo artesanal inspirado na Aardman Animations (Wallace & Gromit, A Fuga das Galinhas).
- Textura de argila com impressões digitais sutis, pequenas imperfeições e ritmo de 12 FPS com iluminação de stop-motion quente.

### 2. \`/paper-animation\` - Diorama de Papel Mecânico
- Cenários em camadas tridimensionais de papel dobrado, engrenagens de papelão e autômatos mecânicos com luz volumétrica.

### 3. \`/song-style-ad\` - Comercial Videoclipe Musical
- Criação de letras com rimas viciantes, jingle chiclete, sincronia de corte na batida e coreografia divertida com o produto.

### 4. \`/talking-object\` - Objeto Falante com Personalidade
- O próprio produto (uma garrafa térmica, um tênis, um pacote de café) ganha olhos expressivos, boca animada e dialoga diretamente com o consumidor com humor autodepreciativo ou conselhos francos.

### 5. \`/skeleton-ads\` - O Esqueleto Cômico
- Um esqueleto bem-humorado em situações cotidianas representando a espera insana por soluções ruins do mercado até descobrir o produto da marca (*"Esperando meu outro fornecedor responder o orçamento..."*).
`
        },
        {
          path: 'rules.json',
          content: JSON.stringify({
            formats: {
              claymation: { fps: 12, style: "plasticine with thumbprints" },
              paper_animation: { fps: 12, style: "mechanical paper automaton" },
              song_style_ad: { bpm: 120, rhyme_scheme: "AABB" },
              talking_object: { tone: "witty_sarcastic", face_style: "stylized expressive mouth" },
              skeleton_ads: { comedy_style: "situational_relatable_humor" }
            }
          }, null, 2)
        },
        {
          path: 'workflow.md',
          content: `# Workflow: Escolha do Formato Criativo
- Para produtos com apelo tátil/infantil/artesanal -> Use \`/claymation\`.
- Para produtos sustentáveis/design/arquitetura -> Use \`/paper-animation\`.
- Para marcas jovens/lifestyle/tendências virais -> Use \`/song-style-ad\`.
- Para produtos funcionais do dia a dia -> Use \`/talking-object\`.
- Para produtos de B2B, tecnologia ou que resolvem dores de lentidão -> Use \`/skeleton-ads\`.
`
        },
        {
          path: 'checklist.md',
          content: `# Checklist de Engajamento
- [ ] O formato desperta estranheza positiva ou sorriso nos primeiros 2 segundos?
- [ ] A piada ou ritmo visual não esconde a marca ou a oferta principal?
- [ ] A execução preserva a qualidade das texturas sem borrões digitais?
`
        }
      ]
    }
  ];

  for (const item of CREATIVE_SKILLS) {
    let existing = db.skills.find((s: any) => s.id === item.id || s.slug === item.slug);
    const builtFiles = item.files.map(f => buildCreativeFile(item.id, f.path, f.content));

    if (!existing) {
      existing = {
        id: item.id,
        name: item.name,
        slug: item.slug,
        description: item.description,
        category: item.category,
        tags: item.tags,
        status: 'ativa',
        installed: true,
        version: '1.0.0',
        author: 'Notion Claude Creative / Firstsys',
        origin: 'notion',
        license: 'Community Creative Commons',
        riskLevel: item.riskLevel,
        securityWarnings: [],
        dependencies: [],
        permissions: item.permissions,
        createdAt: now,
        updatedAt: now,
        files: builtFiles
      };
      db.skills.push(existing);
    } else {
      existing.name = item.name;
      existing.slug = item.slug;
      existing.description = item.description;
      existing.category = item.category;
      existing.tags = Array.from(new Set([...(existing.tags || []), ...item.tags]));
      existing.origin = 'notion';
      existing.license = 'Community Creative Commons';
      existing.files = builtFiles;
      existing.updatedAt = now;
    }

    // Snapshot de versão 1.0.0
    const existingVer = db.skill_versions.find((v: any) => v.skillId === item.id && v.version === '1.0.0');
    if (!existingVer) {
      const filesSnapshot = builtFiles.map(f => ({
        path: f.path,
        sha256: f.sha256,
        sizeBytes: f.sizeBytes,
        name: f.name
      }));
      const sortedHashes = filesSnapshot.map(f => `${f.path}:${f.sha256}`).sort().join('|');
      db.skill_versions.push({
        id: `ver_${item.id.replace('skill_', '')}_1_0_0`,
        skillId: item.id,
        version: '1.0.0',
        changelog: 'Importação inicial da biblioteca Notion Claude Creative Skill Library com múltiplos arquivos',
        snapshotHash: computeSha256(sortedHashes),
        filesSnapshot,
        createdAt: now,
        createdBy: 'Firstsys Notion Importer'
      });
    }

    // Instalação padrão de conexão
    const existingInst = db.skill_installations.find((i: any) => i.skillId === item.id);
    if (!existingInst) {
      db.skill_installations.push({
        id: `inst_${item.id.replace('skill_', '')}_mcp`,
        skillId: item.id,
        contextType: 'mcp',
        contextId: 'conn_firstsys_mcp',
        contextName: 'Firstsys MCP Principal',
        pinnedVersion: '1.0.0',
        status: 'active',
        config: { enabled: true, source: 'notion' },
        grantedPermissions: item.permissions,
        installedAt: now,
        installedBy: 'Firstsys System'
      });
    }

    // Log de auditoria
    db.skill_audit_logs.push({
      id: `audit_${item.id.replace('skill_', '')}_imported_${Date.now()}`,
      skillId: item.id,
      action: 'imported_from_notion',
      details: `Skill ${item.name} importada com sucesso da biblioteca Notion Claude Creative com ${builtFiles.length} arquivos.`,
      actor: 'firstsys_system',
      metadata: { slug: item.slug, filesCount: builtFiles.length },
      createdAt: now
    });
  }

  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
  console.log(`✅ ${CREATIVE_SKILLS.length} skills criativas do Notion importadas e gravadas com sucesso no db.json!`);
}
