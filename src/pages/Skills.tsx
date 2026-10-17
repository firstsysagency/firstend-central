import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Sparkles,
  Search,
  Plus,
  FileCode,
  FileText,
  CheckCircle2,
  Trash2,
  Copy,
  Check,
  X,
  Bot,
  FolderOpen,
  Save,
  ShieldAlert,
  ShieldCheck,
  History,
  Layers,
  ArrowRight,
  ExternalLink,
  RotateCcw,
  LayoutGrid,
  Table as TableIcon,
  Eye,
  Code2,
  Boxes
} from 'lucide-react';
import type { SkillItem, SkillVersion, SkillInstallation, GitImportPreviewResult, SkillAuditLog } from '../types/skills';

function GithubIcon({ size = 16, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
      <path d="M9 18c-4.51 2-5-2-7-2" />
    </svg>
  );
}

const CATEGORIES = [
  { id: 'todas', label: 'Todas as Skills' },
  { id: 'vendas', label: 'Vendas & SDR' },
  { id: 'atendimento', label: 'Atendimento' },
  { id: 'suporte', label: 'Suporte Técnico' },
  { id: 'engenharia', label: 'Engenharia & Código' },
  { id: 'orquestracao', label: 'Orquestração Multiagente' },
  { id: 'automacao', label: 'Automação & Local-First' }
];

const ORIGINS = [
  { id: 'todos', label: 'Todas as Origens' },
  { id: 'propria', label: 'Própria Firstsys' },
  { id: 'curada', label: 'Curadoria Externa' },
  { id: 'importada', label: 'Importada via Git' }
];

export default function Skills() {
  const [skills, setSkills] = useState<SkillItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('todas');
  const [selectedOrigin, setSelectedOrigin] = useState('todos');
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Modal de Detalhes da Skill
  const [selectedSkill, setSelectedSkill] = useState<SkillItem | null>(null);
  const [activeModalTab, setActiveModalTab] = useState<'files' | 'contexts' | 'versions' | 'audit'>('files');
  const [activeFilePath, setActiveFilePath] = useState<string>('SKILL.md');
  const [fileContentEditor, setFileContentEditor] = useState<string>('');
  const [previewMode, setPreviewMode] = useState<'edit' | 'preview'>('edit');
  const [isSavingFile, setIsSavingFile] = useState(false);
  const [copiedFile, setCopiedFile] = useState(false);

  // Gestão Dinâmica de Tags
  const [addingTagSkillId, setAddingTagSkillId] = useState<string | null>(null);
  const [newTagInput, setNewTagInput] = useState('');

  // Sub-abas do Modal de Detalhes
  const [versionsList, setVersionsList] = useState<SkillVersion[]>([]);
  const [installationsList, setInstallationsList] = useState<SkillInstallation[]>([]);
  const [auditLogsList, setAuditLogsList] = useState<SkillAuditLog[]>([]);
  const [diffVersionA, setDiffVersionA] = useState<string>('');
  const [diffVersionB, setDiffVersionB] = useState<string>('');
  const [diffResult, setDiffResult] = useState<any>(null);

  // Modal de Criação Manual
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newSkillName, setNewSkillName] = useState('');
  const [newSkillDesc, setNewSkillDesc] = useState('');
  const [newSkillCategory, setNewSkillCategory] = useState('vendas');
  const [newSkillLicense] = useState('Proprietária Firstsys');
  const [newSkillTags] = useState<string[]>(['ia', 'firstsys']);
  const [newSkillContent, setNewSkillContent] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Modal de Adicionar Novo Arquivo
  const [isAddFileModalOpen, setIsAddFileModalOpen] = useState(false);
  const [newFilePath, setNewFilePath] = useState('');
  const [newFileContent, setNewFileContent] = useState('');

  // Modal de Importação Git (Fluxo em 3 Etapas)
  const [isGitModalOpen, setIsGitModalOpen] = useState(false);
  const [gitStep, setGitStep] = useState<1 | 2>(1);
  const [gitRepoUrl, setGitRepoUrl] = useState('');
  const [isInspectingGit, setIsInspectingGit] = useState(false);
  const [gitPreview, setGitPreview] = useState<GitImportPreviewResult | null>(null);
  const [gitSelectedPaths, setGitSelectedPaths] = useState<string[]>([]);
  const [gitCustomName, setGitCustomName] = useState('');
  const [gitCustomCategory, setGitCustomCategory] = useState('engenharia');
  const [isImportingGit, setIsImportingGit] = useState(false);

  // Modal de Adicionar Instalação por Contexto
  const [isAddContextModalOpen, setIsAddContextModalOpen] = useState(false);
  const [contextType, setContextType] = useState<'agent' | 'connection' | 'project' | 'mcp' | 'environment'>('connection');
  const [contextId, setContextId] = useState('conn_coolify_principal');
  const [contextName, setContextName] = useState('Zatten Produção (Coolify)');
  const [contextPinnedVersion, setContextPinnedVersion] = useState('1.0.0');

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Carregar skills do backend
  const loadSkills = async () => {
    try {
      setIsLoading(true);
      const res = await fetch('/api/skills');
      if (res.ok) {
        const data = await res.json();
        setSkills(data.skills || []);
      }
    } catch (err) {
      console.error('Erro ao carregar catálogo de skills:', err);
      showToast('Falha na comunicação com o servidor de skills.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSkills();
  }, []);

  // Filtragem de skills
  const filteredSkills = useMemo(() => {
    return skills.filter(skill => {
      const matchesCat = selectedCategory === 'todas' || skill.category?.toLowerCase() === selectedCategory.toLowerCase();
      const matchesOrigin = selectedOrigin === 'todos' || skill.origin?.toLowerCase() === selectedOrigin.toLowerCase();
      const q = searchTerm.toLowerCase().trim();
      const matchesSearch = !q ||
        skill.name.toLowerCase().includes(q) ||
        skill.description.toLowerCase().includes(q) ||
        skill.slug.toLowerCase().includes(q) ||
        skill.tags.some(t => t.toLowerCase().includes(q));
      return matchesCat && matchesOrigin && matchesSearch;
    });
  }, [skills, selectedCategory, selectedOrigin, searchTerm]);

  // Abrir Modal de Detalhes da Skill e carregar seus dados
  const handleOpenSkillDetails = async (skill: SkillItem) => {
    setSelectedSkill(skill);
    setActiveModalTab('files');

    const firstFile = skill.files?.find(f => !f.deletedAt)?.path || 'SKILL.md';
    setActiveFilePath(firstFile);
    const fileObj = skill.files?.find(f => f.path === firstFile);
    setFileContentEditor(fileObj?.content || '');

    // Carregar detalhes adicionais
    try {
      const [versRes, instRes, audRes] = await Promise.all([
        fetch(`/api/skills/${skill.id}/versions`),
        fetch(`/api/skills/${skill.id}/installations`),
        fetch(`/api/skills/${skill.id}/audit`)
      ]);

      if (versRes.ok) {
        const d = await versRes.json();
        setVersionsList(d.versions || []);
        if (d.versions && d.versions.length >= 2) {
          setDiffVersionA(d.versions[0].version);
          setDiffVersionB(d.versions[1].version);
        }
      }
      if (instRes.ok) {
        const d = await instRes.json();
        setInstallationsList(d.installations || []);
      }
      if (audRes.ok) {
        const d = await audRes.json();
        setAuditLogsList(d.logs || []);
      }
    } catch (err) {
      console.warn('Erro ao carregar detalhes complementares:', err);
    }
  };

  // Alternar arquivo selecionado no editor
  const handleSelectFile = (filePath: string) => {
    if (!selectedSkill) return;
    setActiveFilePath(filePath);
    const fileObj = selectedSkill.files?.find(f => f.path === filePath);
    setFileContentEditor(fileObj?.content || '');
  };

  // Salvar arquivo editado
  const handleSaveCurrentFile = async () => {
    if (!selectedSkill) return;
    try {
      setIsSavingFile(true);
      const res = await fetch(`/api/skills/${selectedSkill.id}/files`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: activeFilePath,
          content: fileContentEditor
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedSkill(data.skill);
        setSkills(prev => prev.map(s => s.id === data.skill.id ? data.skill : s));
        showToast(`Arquivo "${activeFilePath}" salvo com sucesso!`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao salvar arquivo.');
      }
    } catch {
      showToast('Erro de conexão ao salvar arquivo.');
    } finally {
      setIsSavingFile(false);
    }
  };

  // Adicionar novo arquivo dentro da skill
  const handleAddNewFileSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSkill || !newFilePath.trim()) return;

    try {
      const res = await fetch(`/api/skills/${selectedSkill.id}/files`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: newFilePath.trim(),
          content: newFileContent.trim() || `# ${newFilePath.trim()}\n\nConteúdo inicial.`
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedSkill(data.skill);
        setSkills(prev => prev.map(s => s.id === data.skill.id ? data.skill : s));
        setActiveFilePath(newFilePath.trim());
        setFileContentEditor(newFileContent.trim() || `# ${newFilePath.trim()}\n\nConteúdo inicial.`);
        setNewFilePath('');
        setNewFileContent('');
        setIsAddFileModalOpen(false);
        showToast(`Arquivo "${newFilePath.trim()}" criado com sucesso!`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao adicionar arquivo.');
      }
    } catch {
      showToast('Erro de conexão ao criar arquivo.');
    }
  };

  // Excluir arquivo
  const handleDeleteFile = async (filePath: string) => {
    if (!selectedSkill) return;
    if (filePath.toLowerCase() === 'skill.md') {
      showToast('O arquivo principal SKILL.md não pode ser excluído.');
      return;
    }

    if (!window.confirm(`Deseja mover o arquivo "${filePath}" para a lixeira?`)) return;

    try {
      const res = await fetch(`/api/skills/${selectedSkill.id}/files/${encodeURIComponent(filePath)}`, {
        method: 'DELETE'
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedSkill(data.skill);
        setSkills(prev => prev.map(s => s.id === data.skill.id ? data.skill : s));
        setActiveFilePath('SKILL.md');
        const skillMd = data.skill.files?.find((f: any) => f.path === 'SKILL.md');
        setFileContentEditor(skillMd?.content || '');
        showToast(`Arquivo "${filePath}" movido para a lixeira.`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao remover arquivo.');
      }
    } catch {
      showToast('Erro de conexão ao remover arquivo.');
    }
  };

  // Adicionar Tag Dinâmica
  const handleAddTag = async (skillId: string, tag: string) => {
    const clean = tag.trim().replace(/^#/, '');
    if (!clean) return;

    try {
      const res = await fetch(`/api/skills/${skillId}/tags`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tag: clean })
      });

      if (res.ok) {
        const data = await res.json();
        setSkills(prev => prev.map(s => s.id === skillId ? { ...s, tags: data.tags } : s));
        if (selectedSkill?.id === skillId) {
          setSelectedSkill(prev => prev ? { ...prev, tags: data.tags } : null);
        }
        showToast(`Tag "#${clean}" adicionada com sucesso.`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao adicionar tag.');
      }
    } catch {
      showToast('Erro de conexão ao adicionar tag.');
    }
  };

  // Remover Tag Dinâmica
  const handleRemoveTag = async (skillId: string, tag: string) => {
    try {
      const res = await fetch(`/api/skills/${skillId}/tags/${encodeURIComponent(tag)}`, {
        method: 'DELETE'
      });

      if (res.ok) {
        const data = await res.json();
        setSkills(prev => prev.map(s => s.id === skillId ? { ...s, tags: data.tags } : s));
        if (selectedSkill?.id === skillId) {
          setSelectedSkill(prev => prev ? { ...prev, tags: data.tags } : null);
        }
        showToast(`Tag "#${tag}" removida.`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao remover tag.');
      }
    } catch {
      showToast('Erro de conexão ao remover tag.');
    }
  };

  // Excluir skill da biblioteca
  const handleDeleteSkill = async (skillId: string, skillName: string) => {
    if (!window.confirm(`Deseja realmente arquivar a skill "${skillName}"?`)) return;

    try {
      const res = await fetch(`/api/skills/${skillId}`, { method: 'DELETE' });
      if (res.ok) {
        setSkills(prev => prev.map(s => s.id === skillId ? { ...s, status: 'arquivada' } : s));
        if (selectedSkill?.id === skillId) setSelectedSkill(null);
        showToast(`Skill "${skillName}" arquivada com sucesso.`);
      } else {
        showToast('Não foi possível excluir a skill.');
      }
    } catch {
      showToast('Erro ao excluir skill.');
    }
  };

  // Submeter criação manual de skill
  const handleCreateSkillSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSkillName.trim()) {
      showToast('Por favor, informe o nome da skill.');
      return;
    }

    try {
      setIsSubmitting(true);
      const res = await fetch('/api/skills', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newSkillName.trim(),
          description: newSkillDesc.trim(),
          category: newSkillCategory,
          license: newSkillLicense,
          tags: newSkillTags,
          initialContent: newSkillContent.trim()
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSkills(prev => [data.skill, ...prev]);
        setIsCreateModalOpen(false);
        setNewSkillName('');
        setNewSkillDesc('');
        setNewSkillContent('');
        showToast(`Skill "${data.skill.name}" criada com sucesso!`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao cadastrar skill.');
      }
    } catch {
      showToast('Falha na comunicação com o servidor.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Inspecionar Repositório Git (Preview Seguro)
  const handleInspectGit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!gitRepoUrl.trim()) return;

    try {
      setIsInspectingGit(true);
      const res = await fetch('/api/skills/import/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: gitRepoUrl.trim() })
      });

      if (res.ok) {
        const data = await res.json();
        setGitPreview(data.preview);
        setGitCustomName(data.preview.detectedName || data.preview.repo);
        setGitCustomCategory(data.preview.detectedCategory || 'engenharia');
        setGitSelectedPaths(data.preview.files.filter((f: any) => !f.isIgnored).map((f: any) => f.path));
        setGitStep(2);
      } else {
        const err = await res.json();
        showToast(err.error || 'Não foi possível analisar o repositório Git.');
      }
    } catch {
      showToast('Falha ao conectar com o serviço de importação Git.');
    } finally {
      setIsInspectingGit(false);
    }
  };

  // Efetivar Importação Git
  const handleCommitGitImport = async () => {
    if (!gitPreview || gitSelectedPaths.length === 0) {
      showToast('Selecione ao menos um arquivo para importar.');
      return;
    }

    try {
      setIsImportingGit(true);
      const res = await fetch('/api/skills/import/commit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl: gitPreview.repoUrl,
          selectedPaths: gitSelectedPaths,
          skillName: gitCustomName.trim(),
          category: gitCustomCategory,
          license: gitPreview.license
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSkills(prev => [data.skill, ...prev]);
        setIsGitModalOpen(false);
        setGitStep(1);
        setGitPreview(null);
        setGitRepoUrl('');
        showToast(`Skill "${data.skill.name}" importada com sucesso via Git!`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao importar repositório.');
      }
    } catch {
      showToast('Falha na importação.');
    } finally {
      setIsImportingGit(false);
    }
  };

  // Adicionar Vínculo de Instalação por Contexto
  const handleAddContextInstallation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSkill) return;

    try {
      const res = await fetch(`/api/skills/${selectedSkill.id}/installations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contextType,
          contextId: contextId.trim(),
          contextName: contextName.trim(),
          pinnedVersion: contextPinnedVersion.trim() || selectedSkill.version
        })
      });

      if (res.ok) {
        const data = await res.json();
        setInstallationsList(prev => [...prev, data.installation]);
        setIsAddContextModalOpen(false);
        showToast(`Instalação vinculada com sucesso ao contexto "${contextName}"!`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao vincular instalação.');
      }
    } catch {
      showToast('Erro ao criar instalação.');
    }
  };

  // Remover Instalação por Contexto
  const handleDeleteContextInstallation = async (instId: string) => {
    if (!selectedSkill) return;
    try {
      const res = await fetch(`/api/skills/${selectedSkill.id}/installations/${instId}`, { method: 'DELETE' });
      if (res.ok) {
        setInstallationsList(prev => prev.filter(i => i.id !== instId));
        showToast('Instalação desvinculada com sucesso.');
      }
    } catch {
      showToast('Erro ao remover instalação.');
    }
  };

  // Executar Diff de Versões
  const handleCompareVersions = async () => {
    if (!selectedSkill || !diffVersionA || !diffVersionB) return;
    try {
      const res = await fetch(`/api/skills/${selectedSkill.id}/versions/compare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ versionA: diffVersionA, versionB: diffVersionB })
      });
      if (res.ok) {
        const data = await res.json();
        setDiffResult(data.diff);
      }
    } catch {
      showToast('Erro ao comparar versões.');
    }
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Toast Notification */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            className="fixed top-6 right-6 z-50 flex items-center gap-3 px-5 py-3.5 rounded-xl bg-zinc-900 border border-primary/40 text-foreground shadow-2xl backdrop-blur-md"
          >
            <Sparkles className="text-primary w-5 h-5 flex-shrink-0 animate-pulse" />
            <span className="text-sm font-medium">{toastMessage}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Hero Header Corporativo */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-zinc-900/95 via-zinc-900/60 to-zinc-950 p-8 border border-zinc-800/80 shadow-2xl backdrop-blur-xl">
        <div className="absolute -right-16 -top-16 w-80 h-80 bg-primary/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -left-16 -bottom-16 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold tracking-wide">
              <Boxes size={14} className="animate-spin-slow" />
              Biblioteca Corporativa Universal de Skills & Personas de IA
            </div>
            <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-foreground">
              Skills Firstsys & Agentes
            </h1>
            <p className="text-sm md:text-base text-zinc-400 max-w-2xl leading-relaxed">
              Repositório corporativo universal de capacidades e procedimentos de inteligência artificial para agentes autônomos 
              e projetos de engenharia. Crie pacotes multi-arquivos, importe repositórios Git públicos com varredura de segurança 
              e gerencie tags dinâmicas para segmentação por projeto ou tecnologia.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => {
                setGitStep(1);
                setGitPreview(null);
                setGitRepoUrl('');
                setIsGitModalOpen(true);
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-zinc-800/90 hover:bg-zinc-700/90 text-zinc-200 border border-zinc-700/60 font-semibold shadow-md transition-all duration-300 hover:scale-[1.02] cursor-pointer text-xs"
            >
              <GithubIcon size={16} />
              Importar do Git
            </button>
            <button
              onClick={() => {
                setNewSkillContent(`# Skill: Nova Capacidade\n\n## Objetivo\nDescreva a missão desta skill.\n\n## Instruções para a IA\n1. Atue com cordialidade e precisão.\n2. Consulte os parâmetros operacionais.`);
                setIsCreateModalOpen(true);
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary text-primary-foreground font-semibold shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-all duration-300 hover:scale-[1.02] cursor-pointer text-xs"
            >
              <Plus size={16} />
              Criar Nova Skill
            </button>
          </div>
        </div>

        {/* Resumo de Métricas */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8 pt-6 border-t border-zinc-800/60">
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Catálogo de Skills</span>
            <p className="text-2xl font-bold text-foreground">{skills.length}</p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Ativas / Habilitadas</span>
            <p className="text-2xl font-bold text-emerald-400">{skills.filter(s => s.status === 'ativa' || s.installed).length}</p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Curadas / Git</span>
            <p className="text-2xl font-bold text-cyan-400">{skills.filter(s => s.origin !== 'propria').length}</p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Protocolo MCP</span>
            <p className="text-2xl font-bold text-primary flex items-center gap-1.5">
              <CheckCircle2 size={18} className="text-emerald-400" />
              Catálogo Ativo
            </p>
          </div>
        </div>
      </div>

      {/* Barra de Filtros, Categorias e Modos de Exibição */}
      <div className="space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Categorias Tabs */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-2 lg:pb-0 scrollbar-none">
            {CATEGORIES.map(cat => {
              const isActive = selectedCategory === cat.id;
              return (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  className={`relative px-4 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition-all duration-300 cursor-pointer ${
                    isActive ? 'text-primary-foreground' : 'text-zinc-400 hover:text-foreground hover:bg-white/5'
                  }`}
                >
                  {isActive && (
                    <motion.div
                      layoutId="category-tab"
                      className="absolute inset-0 bg-primary rounded-xl z-0"
                      transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                    />
                  )}
                  <span className="relative z-10">{cat.label}</span>
                </button>
              );
            })}
          </div>

          {/* Campo de Busca e Alternador de Modo de Visualização */}
          <div className="flex items-center gap-3">
            <div className="relative w-full sm:w-72">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-500" size={15} />
              <input
                type="text"
                placeholder="Buscar por nome, slug ou tag..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-xl bg-zinc-900/80 border border-zinc-800 text-foreground placeholder:text-zinc-500 text-xs focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all"
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-foreground"
                >
                  <X size={14} />
                </button>
              )}
            </div>

            <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-xl p-1 gap-1">
              <button
                onClick={() => setViewMode('cards')}
                className={`p-1.5 rounded-lg text-xs transition-colors cursor-pointer ${viewMode === 'cards' ? 'bg-zinc-800 text-primary' : 'text-zinc-400 hover:text-zinc-200'}`}
                title="Visualização em Cards"
              >
                <LayoutGrid size={16} />
              </button>
              <button
                onClick={() => setViewMode('table')}
                className={`p-1.5 rounded-lg text-xs transition-colors cursor-pointer ${viewMode === 'table' ? 'bg-zinc-800 text-primary' : 'text-zinc-400 hover:text-zinc-200'}`}
                title="Visualização em Tabela"
              >
                <TableIcon size={16} />
              </button>
            </div>
          </div>
        </div>

        {/* Filtro secundário por Origem */}
        <div className="flex items-center gap-2 overflow-x-auto text-xs text-zinc-400">
          <span className="font-medium text-zinc-500">Origem:</span>
          {ORIGINS.map(orig => (
            <button
              key={orig.id}
              onClick={() => setSelectedOrigin(orig.id)}
              className={`px-2.5 py-1 rounded-lg border text-xs cursor-pointer transition-all ${
                selectedOrigin === orig.id
                  ? 'bg-zinc-800 border-primary/40 text-primary font-medium'
                  : 'bg-zinc-900/50 border-zinc-800/80 text-zinc-400 hover:text-zinc-300'
              }`}
            >
              {orig.label}
            </button>
          ))}
        </div>
      </div>

      {/* Conteúdo Principal: Cards ou Tabela */}
      {isLoading ? (
        <div className="py-20 flex flex-col items-center justify-center gap-4 text-zinc-500">
          <div className="w-10 h-10 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
          <p className="text-xs uppercase tracking-widest font-mono">Carregando Biblioteca de Skills...</p>
        </div>
      ) : filteredSkills.length === 0 ? (
        <div className="py-16 text-center rounded-2xl border border-dashed border-zinc-800 bg-zinc-950/40 p-8">
          <Bot size={40} className="mx-auto text-zinc-600 mb-3" />
          <h3 className="text-base font-semibold text-foreground">Nenhuma skill encontrada</h3>
          <p className="text-xs text-zinc-500 mt-1 max-w-md mx-auto">
            Não encontramos skills correspondentes aos filtros selecionados. Tente alterar o termo de busca ou adicione uma nova skill.
          </p>
        </div>
      ) : viewMode === 'cards' ? (
        /* Visualização em Grid de Cards Modernos */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredSkills.map(skill => {
            const fileCount = (skill.files || []).filter(f => !f.deletedAt).length;
            const hasExec = (skill.files || []).some(f => f.isExecutable && !f.deletedAt);

            return (
              <motion.div
                key={skill.id}
                layout
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.2 }}
                className="group relative flex flex-col justify-between rounded-2xl bg-zinc-900/60 border border-zinc-800/80 hover:border-zinc-700/80 p-6 shadow-xl backdrop-blur-md transition-all duration-300 hover:shadow-2xl hover:-translate-y-1"
              >
                <div>
                  {/* Top Badges */}
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-300 border border-zinc-700/60">
                      v{skill.version}
                    </span>
                    <div className="flex items-center gap-1.5">
                      {skill.origin === 'importada' ? (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/60 text-cyan-400 border border-cyan-800/60">
                          <GithubIcon size={10} /> Git
                        </span>
                      ) : skill.origin === 'curada' ? (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-purple-950/60 text-purple-400 border border-purple-800/60">
                          <Sparkles size={10} /> Curada
                        </span>
                      ) : (
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-zinc-800/80 text-zinc-400 border border-zinc-700/40">
                          Própria
                        </span>
                      )}

                      {skill.riskLevel === 'alto' && (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-rose-950/60 text-rose-400 border border-rose-800/60">
                          <ShieldAlert size={10} /> Risco
                        </span>
                      )}

                      {skill.installed && (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                          <CheckCircle2 size={10} /> Ativa
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Nome e Descrição */}
                  <h3 className="text-lg font-bold text-foreground group-hover:text-primary transition-colors">
                    {skill.name}
                  </h3>
                  <p className="text-xs text-zinc-400 mt-2 line-clamp-3 leading-relaxed">
                    {skill.description}
                  </p>

                  {/* Tags Dinâmicas com Adição e Remoção */}
                  <div className="flex flex-wrap items-center gap-1.5 mt-4">
                    {skill.tags.map(tag => (
                      <span
                        key={tag}
                        className="group/tag inline-flex items-center gap-1 text-[10px] pl-2 pr-1.5 py-0.5 rounded-md bg-zinc-800/80 text-zinc-300 font-mono border border-zinc-700/60 hover:border-zinc-500 transition-colors"
                      >
                        <span>#{tag}</span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRemoveTag(skill.id, tag);
                          }}
                          className="text-zinc-500 hover:text-rose-400 p-0.5 rounded transition-colors cursor-pointer"
                          title={`Remover tag #${tag}`}
                        >
                          <X size={10} />
                        </button>
                      </span>
                    ))}

                    {addingTagSkillId === skill.id ? (
                      <div className="inline-flex items-center gap-1 bg-zinc-800/90 rounded-md px-1.5 py-0.5 border border-primary/50 shadow-sm">
                        <input
                          type="text"
                          autoFocus
                          placeholder="nova-tag..."
                          value={newTagInput}
                          onChange={e => setNewTagInput(e.target.value)}
                          onKeyDown={e => {
                            if (e.key === 'Enter') {
                              e.preventDefault();
                              handleAddTag(skill.id, newTagInput);
                              setNewTagInput('');
                              setAddingTagSkillId(null);
                            } else if (e.key === 'Escape') {
                              setAddingTagSkillId(null);
                              setNewTagInput('');
                            }
                          }}
                          className="w-20 bg-transparent text-[10px] text-zinc-200 outline-none font-mono"
                        />
                        <button
                          type="button"
                          onClick={() => {
                            handleAddTag(skill.id, newTagInput);
                            setNewTagInput('');
                            setAddingTagSkillId(null);
                          }}
                          className="text-emerald-400 hover:text-emerald-300 cursor-pointer"
                          title="Confirmar"
                        >
                          <Check size={11} />
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setAddingTagSkillId(null);
                            setNewTagInput('');
                          }}
                          className="text-zinc-500 hover:text-zinc-400 cursor-pointer"
                          title="Cancelar"
                        >
                          <X size={11} />
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => {
                          setAddingTagSkillId(skill.id);
                          setNewTagInput('');
                        }}
                        className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-md bg-zinc-800/40 hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300 font-mono border border-dashed border-zinc-700/80 cursor-pointer transition-colors"
                        title="Adicionar tag"
                      >
                        <Plus size={10} /> Tag
                      </button>
                    )}
                  </div>
                </div>

                {/* Footer do Card */}
                <div className="mt-6 pt-4 border-t border-zinc-800/60 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-xs text-zinc-500">
                    <span className="flex items-center gap-1">
                      <FolderOpen size={13} className="text-zinc-400" />
                      {fileCount} {fileCount === 1 ? 'arquivo' : 'arquivos'}
                    </span>
                    {hasExec && (
                      <span className="text-[10px] text-amber-400 font-mono" title="Contém script para análise">
                        [Script]
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleOpenSkillDetails(skill)}
                      className="px-3.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium cursor-pointer transition-colors"
                    >
                      Abrir Arquivos
                    </button>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      ) : (
        /* Visualização em Tabela Compacta */
        <div className="overflow-x-auto rounded-2xl border border-zinc-800 bg-zinc-900/60 backdrop-blur-md shadow-xl">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-900/90 text-zinc-400 uppercase text-[10px] tracking-wider border-b border-zinc-800">
              <tr>
                <th className="py-3 px-4">Nome & Slug</th>
                <th className="py-3 px-4">Categoria</th>
                <th className="py-3 px-4">Origem</th>
                <th className="py-3 px-4">Versão</th>
                <th className="py-3 px-4">Licença</th>
                <th className="py-3 px-4">Arquivos</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {filteredSkills.map(skill => (
                <tr key={skill.id} className="hover:bg-zinc-800/30 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-semibold text-foreground">{skill.name}</div>
                    <div className="text-[10px] font-mono text-zinc-500">{skill.slug}</div>
                  </td>
                  <td className="py-3 px-4 text-zinc-400 capitalize">{skill.category}</td>
                  <td className="py-3 px-4">
                    <span className="capitalize text-zinc-300">{skill.origin}</span>
                  </td>
                  <td className="py-3 px-4 font-mono text-zinc-300">v{skill.version}</td>
                  <td className="py-3 px-4 text-zinc-400">{skill.license}</td>
                  <td className="py-3 px-4 text-zinc-400">{skill.files?.length || 0}</td>
                  <td className="py-3 px-4">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium ${
                      skill.installed ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60' : 'bg-zinc-800 text-zinc-400'
                    }`}>
                      {skill.installed ? 'Ativa' : 'Inativa'}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleOpenSkillDetails(skill)}
                        className="px-2.5 py-1 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs cursor-pointer"
                      >
                        Detalhes
                      </button>
                      <button
                        onClick={() => handleDeleteSkill(skill.id, skill.name)}
                        className="p-1 rounded-md hover:bg-rose-950/60 text-zinc-500 hover:text-rose-400 cursor-pointer"
                        title="Arquivar Skill"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL COMPLETO DE DETALHES DA SKILL (MULTI-ARQUIVOS, VERSÕES, CONTEXTOS) */}
      {/* ==================================================================== */}
      <AnimatePresence>
        {selectedSkill && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              className="relative w-full max-w-6xl max-h-[92vh] flex flex-col rounded-3xl bg-zinc-950 border border-zinc-800 shadow-2xl overflow-hidden"
            >
              {/* Header do Modal */}
              <div className="p-6 border-b border-zinc-800/80 flex items-start justify-between gap-4 bg-zinc-900/50">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-primary/20 text-primary border border-primary/30">
                      v{selectedSkill.version}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">
                      {selectedSkill.category}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">
                      Licença: {selectedSkill.license}
                    </span>
                  </div>
                  <h2 className="text-2xl font-extrabold text-foreground">{selectedSkill.name}</h2>
                  <p className="text-xs text-zinc-400 max-w-3xl">{selectedSkill.description}</p>
                </div>
                <button
                  onClick={() => setSelectedSkill(null)}
                  className="p-2 rounded-xl text-zinc-500 hover:text-foreground hover:bg-zinc-800/80 transition-colors cursor-pointer"
                >
                  <X size={20} />
                </button>
              </div>

              {/* Abas Internas do Modal */}
              <div className="flex items-center px-6 border-b border-zinc-800/80 bg-zinc-900/30 gap-4">
                <button
                  onClick={() => setActiveModalTab('files')}
                  className={`py-3 text-xs font-semibold flex items-center gap-1.5 border-b-2 cursor-pointer transition-all ${
                    activeModalTab === 'files' ? 'border-primary text-primary' : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  <FolderOpen size={14} /> Arquivos & Código
                </button>
                <button
                  onClick={() => setActiveModalTab('contexts')}
                  className={`py-3 text-xs font-semibold flex items-center gap-1.5 border-b-2 cursor-pointer transition-all ${
                    activeModalTab === 'contexts' ? 'border-primary text-primary' : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  <Layers size={14} /> Instalações por Contexto ({installationsList.length})
                </button>
                <button
                  onClick={() => setActiveModalTab('versions')}
                  className={`py-3 text-xs font-semibold flex items-center gap-1.5 border-b-2 cursor-pointer transition-all ${
                    activeModalTab === 'versions' ? 'border-primary text-primary' : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  <History size={14} /> Versões & Diff ({versionsList.length})
                </button>
                <button
                  onClick={() => setActiveModalTab('audit')}
                  className={`py-3 text-xs font-semibold flex items-center gap-1.5 border-b-2 cursor-pointer transition-all ${
                    activeModalTab === 'audit' ? 'border-primary text-primary' : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  <ShieldCheck size={14} /> Segurança & Auditoria
                </button>
              </div>

              {/* Corpo da Aba Selecionada */}
              <div className="flex-1 overflow-y-auto p-6">
                {/* ABA 1: ARQUIVOS & EDITOR */}
                {activeModalTab === 'files' && (
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-6 h-[580px]">
                    {/* Árvore de Arquivos Lateral */}
                    <div className="md:col-span-1 border border-zinc-800/80 rounded-2xl p-4 bg-zinc-900/40 flex flex-col justify-between">
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] uppercase font-mono tracking-wider text-zinc-500 font-semibold">
                            Árvore da Skill
                          </span>
                          <button
                            onClick={() => setIsAddFileModalOpen(true)}
                            className="p-1 rounded bg-zinc-800 hover:bg-zinc-700 text-primary cursor-pointer text-xs"
                            title="Novo Arquivo"
                          >
                            <Plus size={14} />
                          </button>
                        </div>

                        <div className="space-y-1 overflow-y-auto max-h-[460px] pr-1">
                          {selectedSkill.files?.filter(f => !f.deletedAt).map(file => {
                            const isSelected = activeFilePath === file.path;
                            return (
                              <div
                                key={file.id || file.path}
                                onClick={() => handleSelectFile(file.path)}
                                className={`flex items-center justify-between px-3 py-2 rounded-xl text-xs cursor-pointer group transition-colors ${
                                  isSelected
                                    ? 'bg-primary/20 text-primary font-medium border border-primary/30'
                                    : 'text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200'
                                }`}
                              >
                                <div className="flex items-center gap-2 truncate">
                                  {file.path.endsWith('.md') ? (
                                    <FileText size={14} className={isSelected ? 'text-primary' : 'text-zinc-500'} />
                                  ) : (
                                    <FileCode size={14} className={isSelected ? 'text-primary' : 'text-zinc-500'} />
                                  )}
                                  <span className="truncate">{file.path}</span>
                                </div>
                                {file.path.toLowerCase() !== 'skill.md' && (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleDeleteFile(file.path);
                                    }}
                                    className="opacity-0 group-hover:opacity-100 p-1 hover:text-rose-400 text-zinc-500 transition-opacity"
                                    title="Remover arquivo"
                                  >
                                    <Trash2 size={12} />
                                  </button>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      <div className="pt-3 border-t border-zinc-800/60 text-[10px] text-zinc-500 font-mono">
                        Path Traversal: Bloqueado
                      </div>
                    </div>

                    {/* Editor / Visualizador */}
                    <div className="md:col-span-3 border border-zinc-800/80 rounded-2xl bg-zinc-900/30 flex flex-col justify-between overflow-hidden">
                      {/* Barra de Ferramentas do Editor */}
                      <div className="p-3 border-b border-zinc-800/80 bg-zinc-900/70 flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2 truncate text-xs font-mono text-zinc-300">
                          <span className="text-zinc-500 font-sans">Arquivo:</span>
                          <span className="text-primary font-semibold">{activeFilePath}</span>
                        </div>

                        <div className="flex items-center gap-2">
                          {activeFilePath.endsWith('.md') && (
                            <div className="flex items-center bg-zinc-800 rounded-lg p-0.5 text-xs">
                              <button
                                onClick={() => setPreviewMode('edit')}
                                className={`px-2.5 py-1 rounded text-xs cursor-pointer ${previewMode === 'edit' ? 'bg-zinc-700 text-foreground' : 'text-zinc-400'}`}
                              >
                                <Code2 size={13} className="inline mr-1" /> Editar
                              </button>
                              <button
                                onClick={() => setPreviewMode('preview')}
                                className={`px-2.5 py-1 rounded text-xs cursor-pointer ${previewMode === 'preview' ? 'bg-zinc-700 text-foreground' : 'text-zinc-400'}`}
                              >
                                <Eye size={13} className="inline mr-1" /> Visualizar
                              </button>
                            </div>
                          )}

                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(fileContentEditor);
                              setCopiedFile(true);
                              setTimeout(() => setCopiedFile(false), 2000);
                            }}
                            className="p-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 cursor-pointer text-xs"
                            title="Copiar Conteúdo"
                          >
                            {copiedFile ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                          </button>

                          <button
                            onClick={handleSaveCurrentFile}
                            disabled={isSavingFile}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-xs cursor-pointer disabled:opacity-50"
                          >
                            <Save size={13} />
                            {isSavingFile ? 'Salvando...' : 'Salvar Alterações'}
                          </button>
                        </div>
                      </div>

                      {/* Área de Edição ou Preview */}
                      <div className="flex-1 p-4 overflow-y-auto">
                        {previewMode === 'preview' && activeFilePath.endsWith('.md') ? (
                          <div className="prose prose-invert prose-sm max-w-none">
                            <pre className="whitespace-pre-wrap font-sans text-zinc-300 leading-relaxed text-xs">
                              {fileContentEditor}
                            </pre>
                          </div>
                        ) : (
                          <textarea
                            value={fileContentEditor}
                            onChange={e => setFileContentEditor(e.target.value)}
                            className="w-full h-full min-h-[440px] bg-transparent text-zinc-200 font-mono text-xs focus:outline-none resize-none leading-relaxed"
                            placeholder="Insira as instruções ou código..."
                            spellCheck={false}
                          />
                        )}
                      </div>

                      {/* Footer com Metadados Criptográficos */}
                      <div className="p-2.5 border-t border-zinc-800/80 bg-zinc-950/60 px-4 flex items-center justify-between text-[10px] text-zinc-500 font-mono">
                        <span>Caracteres: {fileContentEditor.length}</span>
                        <span>Zero Execução de Scripts no Servidor</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* ABA 2: INSTALAÇÕES POR CONTEXTO */}
                {activeModalTab === 'contexts' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-base font-bold text-foreground">Contextos Conectados</h4>
                        <p className="text-xs text-zinc-400">
                          Instale esta skill separadamente por agente ou conexão, com versões fixadas sem quebrar operações em produção.
                        </p>
                      </div>
                      <button
                        onClick={() => setIsAddContextModalOpen(true)}
                        className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-primary text-primary-foreground text-xs font-semibold cursor-pointer"
                      >
                        <Plus size={14} /> Vincular a Novo Contexto
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {installationsList.length === 0 ? (
                        <div className="col-span-2 text-center py-12 border border-dashed border-zinc-800 rounded-2xl text-zinc-500 text-xs">
                          Nenhum contexto conectado no momento. Vincule a um agente ou à conexão Zatten.
                        </div>
                      ) : (
                        installationsList.map(inst => (
                          <div key={inst.id} className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 flex items-center justify-between">
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                                  {inst.contextType}
                                </span>
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/20 text-primary">
                                  v{inst.pinnedVersion}
                                </span>
                              </div>
                              <div className="text-sm font-semibold text-foreground">{inst.contextName}</div>
                              <div className="text-[10px] text-zinc-500 font-mono">ID: {inst.contextId}</div>
                            </div>
                            <button
                              onClick={() => handleDeleteContextInstallation(inst.id)}
                              className="p-2 text-zinc-500 hover:text-rose-400 rounded-lg hover:bg-zinc-800 cursor-pointer"
                              title="Desvincular"
                            >
                              <Trash2 size={15} />
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                {/* ABA 3: VERSÕES & DIFF */}
                {activeModalTab === 'versions' && (
                  <div className="space-y-6">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                      <div>
                        <h4 className="text-base font-bold text-foreground">Histórico de Versões & Integridade</h4>
                        <p className="text-xs text-zinc-400">Cada alteração gera um snapshot SHA-256 imutável que permite auditoria e rollback.</p>
                      </div>
                    </div>

                    {/* Comparador de Versões (Diff) */}
                    <div className="p-4 rounded-2xl border border-zinc-800 bg-zinc-900/40 space-y-3">
                      <div className="text-xs font-semibold text-foreground flex items-center gap-2">
                        <RotateCcw size={14} className="text-primary" /> Comparar Snapshot entre Versões
                      </div>
                      <div className="flex flex-wrap items-center gap-3">
                        <select
                          value={diffVersionA}
                          onChange={e => setDiffVersionA(e.target.value)}
                          className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-zinc-200"
                        >
                          {versionsList.map(v => (
                            <option key={v.version} value={v.version}>Versão {v.version}</option>
                          ))}
                        </select>
                        <span className="text-xs text-zinc-500">com</span>
                        <select
                          value={diffVersionB}
                          onChange={e => setDiffVersionB(e.target.value)}
                          className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-zinc-200"
                        >
                          {versionsList.map(v => (
                            <option key={v.version} value={v.version}>Versão {v.version}</option>
                          ))}
                        </select>
                        <button
                          onClick={handleCompareVersions}
                          className="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-xs text-zinc-200 cursor-pointer font-medium"
                        >
                          Calcular Diferenças
                        </button>
                      </div>

                      {diffResult && (
                        <div className="mt-3 pt-3 border-t border-zinc-800/80 grid grid-cols-3 gap-3 text-xs">
                          <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-800/40">
                            <span className="text-emerald-400 font-semibold block mb-1">Arquivos Adicionados ({diffResult.addedFiles.length})</span>
                            <div className="font-mono text-[10px] text-zinc-400">{diffResult.addedFiles.join(', ') || 'Nenhum'}</div>
                          </div>
                          <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-800/40">
                            <span className="text-amber-400 font-semibold block mb-1">Arquivos Modificados ({diffResult.modifiedFiles.length})</span>
                            <div className="font-mono text-[10px] text-zinc-400">{diffResult.modifiedFiles.join(', ') || 'Nenhum'}</div>
                          </div>
                          <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-800/40">
                            <span className="text-rose-400 font-semibold block mb-1">Arquivos Removidos ({diffResult.removedFiles.length})</span>
                            <div className="font-mono text-[10px] text-zinc-400">{diffResult.removedFiles.join(', ') || 'Nenhum'}</div>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Timeline de Snapshots */}
                    <div className="space-y-3">
                      {versionsList.map(ver => (
                        <div key={ver.id || ver.version} className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-900/30 flex items-center justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-mono font-bold text-primary">v{ver.version}</span>
                              <span className="text-[10px] text-zinc-500 font-mono">
                                Hash: {ver.snapshotHash ? ver.snapshotHash.substring(0, 12) + '...' : 'N/A'}
                              </span>
                            </div>
                            <div className="text-xs text-zinc-300">{ver.changelog}</div>
                            <div className="text-[10px] text-zinc-500">
                              Arquivos no Snapshot: {ver.filesSnapshot?.length || 0}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ABA 4: AUDITORIA & SEGURANÇA */}
                {activeModalTab === 'audit' && (
                  <div className="space-y-6">
                    <div>
                      <h4 className="text-base font-bold text-foreground">Diagnóstico de Segurança & Rastreabilidade</h4>
                      <p className="text-xs text-zinc-400">Verificação de licenças, segredos bloqueados e trilha de auditoria imutável.</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                      <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 space-y-1">
                        <span className="text-zinc-500 uppercase text-[10px] font-mono">Nível de Risco</span>
                        <div className={`text-sm font-bold capitalize ${
                          selectedSkill.riskLevel === 'alto' ? 'text-rose-400' : selectedSkill.riskLevel === 'medio' ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {selectedSkill.riskLevel}
                        </div>
                      </div>
                      <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 space-y-1">
                        <span className="text-zinc-500 uppercase text-[10px] font-mono">Origem Rastreável</span>
                        <div className="text-sm font-semibold text-zinc-200 capitalize">
                          {selectedSkill.origin}
                        </div>
                        {selectedSkill.repositoryUrl && (
                          <a href={selectedSkill.repositoryUrl} target="_blank" rel="noreferrer" className="text-[10px] text-primary hover:underline flex items-center gap-1 mt-1">
                            {selectedSkill.repositoryUrl} <ExternalLink size={10} />
                          </a>
                        )}
                      </div>
                      <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 space-y-1">
                        <span className="text-zinc-500 uppercase text-[10px] font-mono">Licença de Uso</span>
                        <div className="text-sm font-semibold text-zinc-200">
                          {selectedSkill.license}
                        </div>
                      </div>
                    </div>

                    {/* Trilha de Auditoria */}
                    <div className="space-y-2">
                      <div className="text-xs font-semibold text-zinc-300">Trilha de Auditoria da Skill</div>
                      <div className="max-h-60 overflow-y-auto space-y-1.5 border border-zinc-800 rounded-xl p-3 bg-zinc-900/30">
                        {auditLogsList.length === 0 ? (
                          <div className="text-xs text-zinc-500 text-center py-4">Nenhum evento registrado ainda.</div>
                        ) : (
                          auditLogsList.map(log => (
                            <div key={log.id} className="text-xs flex items-center justify-between py-1 border-b border-zinc-800/40 last:border-0">
                              <span className="text-zinc-300 font-mono">{log.action}: {log.details}</span>
                              <span className="text-[10px] text-zinc-500">{new Date(log.createdAt).toLocaleString()}</span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ==================================================================== */}
      {/* MODAL DE IMPORTAÇÃO GIT (FLUXO GUIADO EM 2 ETAPAS COM PREVIEW & AUDITORIA) */}
      {/* ==================================================================== */}
      <AnimatePresence>
        {isGitModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-2xl rounded-3xl bg-zinc-950 border border-zinc-800 shadow-2xl p-6 space-y-6"
            >
              <div className="flex items-center justify-between border-b border-zinc-800/80 pb-4">
                <div className="flex items-center gap-2">
                  <GithubIcon size={20} className="text-primary" />
                  <h3 className="text-lg font-bold text-foreground">Importar Skill de Repositório Git</h3>
                </div>
                <button
                  onClick={() => setIsGitModalOpen(false)}
                  className="p-1 rounded-lg text-zinc-500 hover:text-foreground cursor-pointer"
                >
                  <X size={18} />
                </button>
              </div>

              {gitStep === 1 ? (
                /* Etapa 1: Inserir URL e Validar Anti-SSRF */
                <form onSubmit={handleInspectGit} className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-zinc-300">URL do Repositório (GitHub / GitLab)</label>
                    <input
                      type="url"
                      required
                      placeholder="https://github.com/owner/repository"
                      value={gitRepoUrl}
                      onChange={e => setGitRepoUrl(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    />
                    <p className="text-[11px] text-zinc-500">
                      Proteção anti-SSRF ativa: Apenas repositórios oficiais são aceitos. Redes internas, localhost e metadados são bloqueados.
                    </p>
                  </div>

                  <div className="flex justify-end gap-3 pt-3">
                    <button
                      type="button"
                      onClick={() => setIsGitModalOpen(false)}
                      className="px-4 py-2 rounded-xl bg-zinc-900 text-zinc-400 text-xs font-medium cursor-pointer"
                    >
                      Cancelar
                    </button>
                    <button
                      type="submit"
                      disabled={isInspectingGit}
                      className="px-5 py-2 rounded-xl bg-primary text-primary-foreground text-xs font-semibold cursor-pointer disabled:opacity-50 flex items-center gap-2"
                    >
                      {isInspectingGit ? 'Analisando...' : 'Inspecionar Repositório'} <ArrowRight size={14} />
                    </button>
                  </div>
                </form>
              ) : (
                /* Etapa 2: Revisão de Riscos, Secret Scanning e Seleção de Arquivos */
                gitPreview && (
                  <div className="space-y-4">
                    <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/50 space-y-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-foreground">{gitPreview.owner}/{gitPreview.repo}</span>
                        <span className="font-mono text-[10px] text-zinc-400">Branch: {gitPreview.branch}</span>
                      </div>
                      <p className="text-zinc-400 text-[11px]">{gitPreview.detectedDescription}</p>
                      <div className="flex items-center gap-3 pt-1 text-[11px] text-zinc-500 font-mono">
                        <span>Licença: {gitPreview.license}</span>
                        <span>Arquivos: {gitPreview.files.length}</span>
                        <span>Ignorados: {gitPreview.ignoredCount}</span>
                      </div>
                    </div>

                    {gitPreview.securityFindings.length > 0 && (
                      <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 space-y-1">
                        <div className="font-bold flex items-center gap-1.5 text-rose-400">
                          <ShieldAlert size={14} /> Segredos ou Credenciais Detectados!
                        </div>
                        <p className="text-[11px]">
                          Foram detectados {gitPreview.securityFindings.length} potenciais segredos no repositório. Arquivos sensíveis (.env, chaves) foram ignorados automaticamente.
                        </p>
                      </div>
                    )}

                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-zinc-300">Nome de Exibição na Biblioteca</label>
                      <input
                        type="text"
                        value={gitCustomName}
                        onChange={e => setGitCustomName(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-zinc-200"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-zinc-300">
                        Seleção de Arquivos a Importar ({gitSelectedPaths.length} selecionados)
                      </label>
                      <div className="max-h-48 overflow-y-auto border border-zinc-800 rounded-xl p-2 bg-zinc-900/30 space-y-1">
                        {gitPreview.files.filter(f => !f.isIgnored).map(file => (
                          <label key={file.path} className="flex items-center gap-2 p-1.5 hover:bg-zinc-800/40 rounded text-xs text-zinc-300 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={gitSelectedPaths.includes(file.path)}
                              onChange={e => {
                                if (e.target.checked) {
                                  setGitSelectedPaths([...gitSelectedPaths, file.path]);
                                } else {
                                  setGitSelectedPaths(gitSelectedPaths.filter(p => p !== file.path));
                                }
                              }}
                            />
                            <span className="font-mono text-[11px] truncate">{file.path}</span>
                            <span className="text-[10px] text-zinc-500 ml-auto">{Math.round(file.sizeBytes / 1024)} KB</span>
                          </label>
                        ))}
                      </div>
                    </div>

                    <div className="flex justify-between items-center pt-3 border-t border-zinc-800/80">
                      <button
                        onClick={() => setGitStep(1)}
                        className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer"
                      >
                        Voltar
                      </button>
                      <button
                        onClick={handleCommitGitImport}
                        disabled={isImportingGit || gitSelectedPaths.length === 0}
                        className="px-5 py-2 rounded-xl bg-primary text-primary-foreground text-xs font-semibold cursor-pointer disabled:opacity-50"
                      >
                        {isImportingGit ? 'Importando...' : 'Efetivar Importação Segura'}
                      </button>
                    </div>
                  </div>
                )
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ==================================================================== */}
      {/* MODAL DE CRIAÇÃO MANUAL DE SKILL */}
      {/* ==================================================================== */}
      <AnimatePresence>
        {isCreateModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-2xl rounded-3xl bg-zinc-950 border border-zinc-800 shadow-2xl p-6 space-y-5"
            >
              <div className="flex items-center justify-between border-b border-zinc-800/80 pb-4">
                <h3 className="text-lg font-bold text-foreground">Nova Skill na Biblioteca Firstsys</h3>
                <button onClick={() => setIsCreateModalOpen(false)} className="text-zinc-500 hover:text-foreground">
                  <X size={18} />
                </button>
              </div>

              <form onSubmit={handleCreateSkillSubmit} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-zinc-300">Nome da Skill</label>
                    <input
                      type="text"
                      required
                      placeholder="Ex: Análise de Contratos"
                      value={newSkillName}
                      onChange={e => setNewSkillName(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-zinc-300">Categoria</label>
                    <select
                      value={newSkillCategory}
                      onChange={e => setNewSkillCategory(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    >
                      <option value="vendas">Vendas & SDR</option>
                      <option value="atendimento">Atendimento</option>
                      <option value="suporte">Suporte Técnico</option>
                      <option value="engenharia">Engenharia & Código</option>
                      <option value="orquestracao">Orquestração Multiagente</option>
                      <option value="automacao">Automação & Local-First</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-zinc-300">Descrição Curta</label>
                  <input
                    type="text"
                    required
                    placeholder="Propósito e resultado esperado desta skill de IA"
                    value={newSkillDesc}
                    onChange={e => setNewSkillDesc(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-zinc-300">Instruções Iniciais (SKILL.md)</label>
                  <textarea
                    rows={6}
                    value={newSkillContent}
                    onChange={e => setNewSkillContent(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground font-mono focus:outline-none focus:border-primary/50 resize-none"
                  />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsCreateModalOpen(false)}
                    className="px-4 py-2 rounded-xl bg-zinc-900 text-zinc-400 text-xs font-medium cursor-pointer"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="px-5 py-2 rounded-xl bg-primary text-primary-foreground text-xs font-semibold cursor-pointer disabled:opacity-50"
                  >
                    {isSubmitting ? 'Criando...' : 'Cadastrar Skill'}
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ==================================================================== */}
      {/* MODAL PARA ADICIONAR NOVO ARQUIVO DENTRO DA SKILL */}
      {/* ==================================================================== */}
      <AnimatePresence>
        {isAddFileModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-md rounded-2xl bg-zinc-950 border border-zinc-800 shadow-2xl p-6 space-y-4"
            >
              <h3 className="text-base font-bold text-foreground">Novo Arquivo na Skill</h3>
              <form onSubmit={handleAddNewFileSubmit} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-zinc-300">Caminho Relativo</label>
                  <input
                    type="text"
                    required
                    placeholder="ex: rules.json ou prompts/sondagem.md"
                    value={newFilePath}
                    onChange={e => setNewFilePath(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-foreground font-mono"
                  />
                  <p className="text-[10px] text-zinc-500">
                    Extensões permitidas: .md, .json, .ts, .py, .sql, etc.
                  </p>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsAddFileModalOpen(false)}
                    className="px-3 py-1.5 rounded-lg bg-zinc-900 text-zinc-400 text-xs cursor-pointer"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-semibold cursor-pointer"
                  >
                    Criar Arquivo
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ==================================================================== */}
      {/* MODAL PARA VINCULAR INSTALAÇÃO POR CONTEXTO */}
      {/* ==================================================================== */}
      <AnimatePresence>
        {isAddContextModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-md rounded-2xl bg-zinc-950 border border-zinc-800 shadow-2xl p-6 space-y-4"
            >
              <h3 className="text-base font-bold text-foreground">Vincular Skill a um Contexto</h3>
              <form onSubmit={handleAddContextInstallation} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-zinc-300">Tipo de Contexto</label>
                  <select
                    value={contextType}
                    onChange={e => setContextType(e.target.value as any)}
                    className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-foreground"
                  >
                    <option value="connection">Conexão Zatten (Coolify)</option>
                    <option value="agent">Agente Específico</option>
                    <option value="project">Projeto de Desenvolvimento</option>
                    <option value="mcp">Servidor MCP Interno</option>
                    <option value="environment">Ambiente (Teste/Prod)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-zinc-300">Nome de Exibição do Contexto</label>
                  <input
                    type="text"
                    required
                    placeholder="Ex: Agente Comercial WhatsApp"
                    value={contextName}
                    onChange={e => setContextName(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-foreground"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-zinc-300">Identificador do Contexto (ID)</label>
                  <input
                    type="text"
                    required
                    placeholder="Ex: agent_sdr_01 ou conn_coolify_principal"
                    value={contextId}
                    onChange={e => setContextId(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-foreground font-mono"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-zinc-300">Versão Semântica Fixada</label>
                  <input
                    type="text"
                    required
                    placeholder="Ex: 1.0.0"
                    value={contextPinnedVersion}
                    onChange={e => setContextPinnedVersion(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-foreground font-mono"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsAddContextModalOpen(false)}
                    className="px-3 py-1.5 rounded-lg bg-zinc-900 text-zinc-400 text-xs cursor-pointer"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-semibold cursor-pointer"
                  >
                    Vincular Contexto
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
