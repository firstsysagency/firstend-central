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
  Save
} from 'lucide-react';
import { logAuditEvent } from '../lib/audit';

export interface SkillFile {
  name: string;
  path: string;
  language: string;
  content: string;
  updatedAt: string;
}

export interface SkillItem {
  id: string;
  name: string;
  slug: string;
  description: string;
  category: string;
  tags: string[];
  status: 'active' | 'inactive' | 'draft';
  installed: boolean;
  version: string;
  author: string;
  createdAt: string;
  updatedAt: string;
  files: SkillFile[];
}

const CATEGORIES = [
  { id: 'todas', label: 'Todas as Skills' },
  { id: 'vendas', label: 'Vendas & SDR' },
  { id: 'atendimento', label: 'Atendimento' },
  { id: 'suporte', label: 'Suporte Técnico' },
  { id: 'automacao', label: 'Automação & CRM' }
];

export default function Skills() {
  const [skills, setSkills] = useState<SkillItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('todas');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Estados de Modais
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [selectedSkillForFiles, setSelectedSkillForFiles] = useState<SkillItem | null>(null);
  const [activeFileTab, setActiveFileTab] = useState<string>('SKILL.md');
  const [fileContentEditor, setFileContentEditor] = useState<string>('');
  const [isSavingFile, setIsSavingFile] = useState(false);
  const [copiedFile, setCopiedFile] = useState(false);

  // Estados do formulário de criação
  const [newSkillName, setNewSkillName] = useState('');
  const [newSkillDesc, setNewSkillDesc] = useState('');
  const [newSkillCategory, setNewSkillCategory] = useState('vendas');
  const [newSkillTagInput, setNewSkillTagInput] = useState('');
  const [newSkillTags, setNewSkillTags] = useState<string[]>(['whatsapp', 'zatten']);
  const [newSkillContent, setNewSkillContent] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Modal de adicionar novo arquivo à skill
  const [isAddFileModalOpen, setIsAddFileModalOpen] = useState(false);
  const [newFileName, setNewFileName] = useState('');

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
      console.error('Erro ao carregar skills:', err);
      showToast('Falha ao conectar com o serviço de skills.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSkills();
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Filtragem de skills
  const filteredSkills = useMemo(() => {
    return skills.filter(skill => {
      const matchesCat = selectedCategory === 'todas' || skill.category?.toLowerCase() === selectedCategory.toLowerCase();
      const q = searchTerm.toLowerCase();
      const matchesSearch = !q ||
        skill.name.toLowerCase().includes(q) ||
        skill.description.toLowerCase().includes(q) ||
        skill.tags.some(t => t.toLowerCase().includes(q));
      return matchesCat && matchesSearch;
    });
  }, [skills, selectedCategory, searchTerm]);

  // Alternar instalação de skill
  const handleToggleInstall = async (skillId: string) => {
    try {
      const res = await fetch(`/api/skills/${skillId}/toggle-install`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setSkills(prev => prev.map(s => s.id === skillId ? { ...s, installed: data.installed, status: data.skill.status } : s));
        showToast(data.installed ? 'Skill ativada e pronta para o ChatGPT!' : 'Skill desativada.');
        logAuditEvent({
          actor: 'usuario',
          action: data.installed ? 'skill.installed' : 'skill.uninstalled',
          category: 'api_usage',
          severity: 'info',
          description: `Skill ${skillId} teve status alternado para ${data.installed ? 'ativa' : 'inativa'}`,
          ipAddress: '127.0.0.1'
        });
      }
    } catch (e) {
      showToast('Erro ao alternar status da skill.');
    }
  };

  // Excluir skill
  const handleDeleteSkill = async (skillId: string, skillName: string) => {
    if (!window.confirm(`Deseja realmente excluir a skill "${skillName}"? Esta ação é irreversível.`)) {
      return;
    }

    try {
      const res = await fetch(`/api/skills/${skillId}`, { method: 'DELETE' });
      if (res.ok) {
        setSkills(prev => prev.filter(s => s.id !== skillId));
        if (selectedSkillForFiles?.id === skillId) {
          setSelectedSkillForFiles(null);
        }
        showToast(`Skill "${skillName}" removida com sucesso.`);
      } else {
        showToast('Não foi possível excluir a skill.');
      }
    } catch {
      showToast('Erro ao excluir skill.');
    }
  };

  // Abrir visualizador/editor de arquivos
  const handleOpenFilesModal = (skill: SkillItem) => {
    setSelectedSkillForFiles(skill);
    const initialFile = skill.files?.[0]?.name || 'SKILL.md';
    setActiveFileTab(initialFile);
    const fileObj = skill.files?.find(f => f.name === initialFile);
    setFileContentEditor(fileObj?.content || '');
  };

  // Alternar aba de arquivo no visualizador
  const handleSelectFileTab = (fileName: string) => {
    setActiveFileTab(fileName);
    const fileObj = selectedSkillForFiles?.files?.find(f => f.name === fileName);
    setFileContentEditor(fileObj?.content || '');
  };

  // Salvar alterações no arquivo
  const handleSaveFileContent = async () => {
    if (!selectedSkillForFiles) return;
    try {
      setIsSavingFile(true);
      const res = await fetch(`/api/skills/${selectedSkillForFiles.id}/files`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: activeFileTab,
          content: fileContentEditor
        })
      });

      if (res.ok) {
        const data = await res.json();
        // Atualiza a skill localmente
        setSelectedSkillForFiles(data.skill);
        setSkills(prev => prev.map(s => s.id === data.skill.id ? data.skill : s));
        showToast(`Arquivo "${activeFileTab}" salvo com sucesso!`);
      } else {
        showToast('Erro ao salvar arquivo.');
      }
    } catch {
      showToast('Falha na conexão ao salvar arquivo.');
    } finally {
      setIsSavingFile(false);
    }
  };

  // Adicionar novo arquivo à skill
  const handleAddNewFile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSkillForFiles || !newFileName.trim()) return;

    try {
      const res = await fetch(`/api/skills/${selectedSkillForFiles.id}/files`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newFileName.trim(),
          content: `# ${newFileName.trim()}\n\nConteúdo inicial.`
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedSkillForFiles(data.skill);
        setSkills(prev => prev.map(s => s.id === data.skill.id ? data.skill : s));
        setActiveFileTab(newFileName.trim());
        setFileContentEditor(`# ${newFileName.trim()}\n\nConteúdo inicial.`);
        setNewFileName('');
        setIsAddFileModalOpen(false);
        showToast(`Arquivo "${newFileName.trim()}" criado com sucesso!`);
      }
    } catch {
      showToast('Erro ao adicionar arquivo.');
    }
  };

  // Excluir arquivo secundário da skill
  const handleDeleteFile = async (fileName: string) => {
    if (!selectedSkillForFiles) return;
    if (fileName.toLowerCase() === 'skill.md') {
      showToast('O arquivo principal SKILL.md não pode ser removido.');
      return;
    }

    if (!window.confirm(`Deseja remover o arquivo "${fileName}" desta skill?`)) return;

    try {
      const res = await fetch(`/api/skills/${selectedSkillForFiles.id}/files/${encodeURIComponent(fileName)}`, {
        method: 'DELETE'
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedSkillForFiles(data.skill);
        setSkills(prev => prev.map(s => s.id === data.skill.id ? data.skill : s));
        setActiveFileTab('SKILL.md');
        const skillMd = data.skill.files?.find((f: any) => f.name === 'SKILL.md');
        setFileContentEditor(skillMd?.content || '');
        showToast(`Arquivo "${fileName}" removido.`);
      }
    } catch {
      showToast('Erro ao excluir arquivo.');
    }
  };

  // Criar nova skill
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
        showToast(`Skill "${data.skill.name}" criada e instalada com sucesso!`);
      } else {
        const errData = await res.json();
        showToast(errData.error || 'Erro ao criar skill.');
      }
    } catch {
      showToast('Falha na comunicação com o servidor.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Adicionar tag no formulário de criação
  const handleAddTag = () => {
    const trimmed = newSkillTagInput.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (trimmed && !newSkillTags.includes(trimmed)) {
      setNewSkillTags([...newSkillTags, trimmed]);
      setNewSkillTagInput('');
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

      {/* Hero Header */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-zinc-900/90 via-zinc-900/50 to-zinc-950 p-8 border border-zinc-800/80 shadow-2xl backdrop-blur-xl">
        <div className="absolute -right-16 -top-16 w-80 h-80 bg-primary/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -left-16 -bottom-16 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold tracking-wide">
              <Sparkles size={14} className="animate-spin-slow" />
              Catálogo de Habilidades Operacionais & IA
            </div>
            <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-foreground">
              Skills de Atendimento & Vendas
            </h1>
            <p className="text-sm md:text-base text-zinc-400 max-w-2xl leading-relaxed">
              Guarde, edite e organize os pacotes de instrução <code className="text-primary font-mono text-xs bg-primary/10 px-1.5 py-0.5 rounded">SKILL.md</code>. 
              As skills ativas ficam instantaneamente disponíveis no MCP para que o ChatGPT e agentes da Zatten operem com excelência.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => {
                setNewSkillContent(`# Skill: Nova Capacidade\n\n## Objetivo\nDescreva a missão desta skill.\n\n## Instruções para o ChatGPT\n1. Atue com cordialidade.\n2. Colete os dados do lead.`);
                setIsCreateModalOpen(true);
              }}
              className="flex items-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary text-primary-foreground font-semibold shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-all duration-300 hover:scale-[1.02] cursor-pointer text-sm"
            >
              <Plus size={18} />
              Criar Nova Skill
            </button>
          </div>
        </div>

        {/* Resumo de Métricas Rápidas */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8 pt-6 border-t border-zinc-800/60">
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Total de Skills</span>
            <p className="text-2xl font-bold text-foreground">{skills.length}</p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Instaladas / Ativas</span>
            <p className="text-2xl font-bold text-emerald-400">{skills.filter(s => s.installed).length}</p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Arquivos Gerenciados</span>
            <p className="text-2xl font-bold text-cyan-400">{skills.reduce((acc, s) => acc + (s.files?.length || 0), 0)}</p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">MCP Disponível</span>
            <p className="text-2xl font-bold text-primary flex items-center gap-1.5">
              <CheckCircle2 size={18} className="text-emerald-400" />
              Conectado
            </p>
          </div>
        </div>
      </div>

      {/* Barra de Busca e Filtros de Categoria */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Categorias Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-2 md:pb-0 scrollbar-none">
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

        {/* Campo de Busca */}
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-500" size={16} />
          <input
            type="text"
            placeholder="Buscar por nome, tag ou instrução..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-zinc-900/80 border border-zinc-800 text-foreground placeholder:text-zinc-500 text-xs focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all"
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
      </div>

      {/* Grid de Skills */}
      {isLoading ? (
        <div className="py-20 flex flex-col items-center justify-center gap-4 text-zinc-500">
          <div className="w-10 h-10 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
          <p className="text-xs uppercase tracking-widest font-mono">Carregando Skills...</p>
        </div>
      ) : filteredSkills.length === 0 ? (
        <div className="py-16 text-center rounded-2xl border border-dashed border-zinc-800 bg-zinc-950/40 p-8">
          <Bot size={40} className="mx-auto text-zinc-600 mb-3" />
          <h3 className="text-base font-semibold text-foreground">Nenhuma skill encontrada</h3>
          <p className="text-xs text-zinc-500 max-w-md mx-auto mt-1 mb-5">
            {searchTerm
              ? 'Nenhum resultado corresponde à sua pesquisa. Tente buscar por outros termos ou limpar os filtros.'
              : 'Você ainda não cadastrou nenhuma skill nesta categoria. Crie uma nova para turbinar as respostas da IA.'}
          </p>
          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-primary/10 border border-primary/30 hover:bg-primary/20 text-primary text-xs font-semibold cursor-pointer transition-colors"
          >
            <Plus size={14} />
            Criar Primeira Skill
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredSkills.map(skill => (
            <motion.div
              key={skill.id}
              layout
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.2 }}
              className={`group relative rounded-2xl p-6 border transition-all duration-300 flex flex-col justify-between ${
                skill.installed
                  ? 'bg-gradient-to-b from-zinc-900/90 to-zinc-950 border-zinc-800 hover:border-primary/40 shadow-lg hover:shadow-primary/5'
                  : 'bg-zinc-950/60 border-zinc-900 opacity-80 hover:opacity-100 hover:border-zinc-800'
              }`}
            >
              <div>
                {/* Cabeçalho do Card */}
                <div className="flex items-start justify-between gap-3 mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-sm shadow-md ${
                      skill.installed
                        ? 'bg-primary/15 text-primary border border-primary/30'
                        : 'bg-zinc-800 text-zinc-400 border border-zinc-700/50'
                    }`}>
                      <Sparkles size={18} />
                    </div>
                    <div>
                      <h3 className="font-bold text-foreground text-sm group-hover:text-primary transition-colors">
                        {skill.name}
                      </h3>
                      <div className="flex items-center gap-2 text-xs text-zinc-500 font-mono mt-0.5">
                        <span>v{skill.version}</span>
                        <span>•</span>
                        <span className="capitalize">{skill.category}</span>
                      </div>
                    </div>
                  </div>

                  {/* Switch de Instalação */}
                  <button
                    onClick={() => handleToggleInstall(skill.id)}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors cursor-pointer focus:outline-none ${
                      skill.installed ? 'bg-primary' : 'bg-zinc-800'
                    }`}
                    title={skill.installed ? 'Skill ativa no MCP' : 'Skill inativa'}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                        skill.installed ? 'translate-x-6' : 'translate-x-1'
                      }`}
                    />
                  </button>
                </div>

                {/* Descrição */}
                <p className="text-xs text-zinc-400 line-clamp-3 mb-4 leading-relaxed">
                  {skill.description || 'Sem descrição cadastrada.'}
                </p>

                {/* Tags */}
                {skill.tags && skill.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mb-4">
                    {skill.tags.map(tag => (
                      <span
                        key={tag}
                        className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-zinc-800/80 text-zinc-400 border border-zinc-700/50"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Rodapé do Card com Arquivos e Ações */}
              <div className="pt-4 border-t border-zinc-800/60 flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5 text-zinc-400 font-mono text-[11px]">
                  <FolderOpen size={13} className="text-zinc-500" />
                  <span>{skill.files?.length || 0} arquivo(s)</span>
                  <span className="text-zinc-600">•</span>
                  <span className="text-primary font-sans">{skill.files?.[0]?.name || 'SKILL.md'}</span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleOpenFilesModal(skill)}
                    className="p-1.5 rounded-lg bg-zinc-800/60 hover:bg-zinc-800 text-zinc-300 hover:text-primary transition-colors cursor-pointer"
                    title="Visualizar e editar arquivos da skill"
                  >
                    <FileCode size={15} />
                  </button>
                  <button
                    onClick={() => handleDeleteSkill(skill.id, skill.name)}
                    className="p-1.5 rounded-lg bg-zinc-800/60 hover:bg-red-500/10 text-zinc-400 hover:text-red-400 transition-colors cursor-pointer"
                    title="Excluir skill"
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* ===================================================================== */}
      {/* MODAL / VISUALIZADOR & EDITOR DE ARQUIVOS DE SKILL (IDE STYLE) */}
      {/* ===================================================================== */}
      <AnimatePresence>
        {selectedSkillForFiles && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              className="relative w-full max-w-4xl h-[85vh] bg-zinc-950 border border-zinc-800 rounded-3xl shadow-2xl flex flex-col overflow-hidden"
            >
              {/* Topo do Visualizador */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800 bg-zinc-900/80">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                    <FileCode size={18} />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-foreground flex items-center gap-2">
                      {selectedSkillForFiles.name}
                      <span className="text-[10px] font-mono text-zinc-500 bg-zinc-800 px-2 py-0.5 rounded">
                        v{selectedSkillForFiles.version}
                      </span>
                    </h2>
                    <p className="text-[11px] text-zinc-400 font-mono">
                      ID: {selectedSkillForFiles.id}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(fileContentEditor);
                      setCopiedFile(true);
                      setTimeout(() => setCopiedFile(false), 2000);
                      showToast('Conteúdo copiado para a área de transferência!');
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium cursor-pointer transition-colors"
                  >
                    {copiedFile ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                    {copiedFile ? 'Copiado!' : 'Copiar'}
                  </button>
                  <button
                    onClick={handleSaveFileContent}
                    disabled={isSavingFile}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-semibold cursor-pointer transition-colors shadow-md shadow-primary/20 disabled:opacity-50"
                  >
                    <Save size={14} />
                    {isSavingFile ? 'Salvando...' : 'Salvar Alterações'}
                  </button>
                  <button
                    onClick={() => setSelectedSkillForFiles(null)}
                    className="p-1.5 rounded-lg text-zinc-400 hover:text-foreground hover:bg-white/5 cursor-pointer"
                  >
                    <X size={18} />
                  </button>
                </div>
              </div>

              {/* Abas dos Arquivos (Tabs) */}
              <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-800/80 bg-zinc-900/40">
                <div className="flex items-center gap-1 overflow-x-auto scrollbar-none">
                  {(selectedSkillForFiles.files || []).map(file => {
                    const isActive = activeFileTab === file.name;
                    return (
                      <div
                        key={file.name}
                        className={`group flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                          isActive
                            ? 'bg-zinc-800 text-primary border border-zinc-700 font-semibold shadow-sm'
                            : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
                        }`}
                        onClick={() => handleSelectFileTab(file.name)}
                      >
                        <FileText size={13} className={isActive ? 'text-primary' : 'text-zinc-500'} />
                        <span>{file.name}</span>
                        {file.name.toLowerCase() !== 'skill.md' && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteFile(file.name);
                            }}
                            className="opacity-0 group-hover:opacity-100 p-0.5 hover:text-red-400 transition-opacity"
                            title="Remover arquivo"
                          >
                            <X size={11} />
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>

                <button
                  onClick={() => setIsAddFileModalOpen(true)}
                  className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-mono cursor-pointer transition-colors"
                  title="Criar novo arquivo nesta skill"
                >
                  <Plus size={12} />
                  <span>Novo Arquivo</span>
                </button>
              </div>

              {/* Editor Monospace */}
              <div className="flex-1 relative p-4 bg-zinc-950 font-mono text-xs overflow-hidden flex flex-col">
                <div className="flex items-center justify-between text-[11px] text-zinc-500 mb-2 font-mono">
                  <span>Editando: <strong className="text-zinc-300">{activeFileTab}</strong></span>
                  <span>{fileContentEditor.length} caracteres • {fileContentEditor.split('\n').length} linhas</span>
                </div>
                <textarea
                  value={fileContentEditor}
                  onChange={e => setFileContentEditor(e.target.value)}
                  className="flex-1 w-full p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-primary/50 resize-none font-mono text-xs leading-relaxed selection:bg-primary/30"
                  placeholder="Escreva as instruções da skill em Markdown ou formato de código..."
                  spellCheck={false}
                />
              </div>

              {/* Barra de Status Inferior */}
              <div className="px-6 py-2.5 border-t border-zinc-800/80 bg-zinc-900/50 flex items-center justify-between text-[11px] text-zinc-500 font-mono">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                  Sincronizado com MCP Zatten Central
                </span>
                <span>Modificações entram em vigor no próximo prompt do ChatGPT</span>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ===================================================================== */}
      {/* MODAL ADICIONAR ARQUIVO */}
      {/* ===================================================================== */}
      <AnimatePresence>
        {isAddFileModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-2xl p-6 shadow-2xl space-y-4"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
                  <FileText size={16} className="text-primary" />
                  Adicionar Arquivo à Skill
                </h3>
                <button onClick={() => setIsAddFileModalOpen(false)} className="text-zinc-400 hover:text-foreground">
                  <X size={16} />
                </button>
              </div>

              <form onSubmit={handleAddNewFile} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-zinc-400 block mb-1.5">Nome do Arquivo com Extensão</label>
                  <input
                    type="text"
                    required
                    placeholder="Ex: rules.json, prompt_suporte.txt, FAQ.md"
                    value={newFileName}
                    onChange={e => setNewFileName(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50 font-mono"
                  />
                </div>

                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsAddFileModalOpen(false)}
                    className="px-4 py-2 rounded-xl text-xs text-zinc-400 hover:bg-white/5"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 rounded-xl bg-primary text-primary-foreground text-xs font-semibold shadow-md shadow-primary/20 hover:bg-primary/90"
                  >
                    Criar Arquivo
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ===================================================================== */}
      {/* MODAL CRIAR NOVA SKILL */}
      {/* ===================================================================== */}
      <AnimatePresence>
        {isCreateModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md overflow-y-auto">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              className="relative w-full max-w-2xl bg-zinc-950 border border-zinc-800 rounded-3xl p-6 md:p-8 shadow-2xl space-y-6 my-8"
            >
              <div className="flex items-center justify-between border-b border-zinc-800/80 pb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                    <Sparkles size={20} />
                  </div>
                  <div>
                    <h2 className="text-base font-bold text-foreground">Criar Nova Skill de IA</h2>
                    <p className="text-xs text-zinc-400">Configure as diretrizes operacionais e o arquivo inicial SKILL.md.</p>
                  </div>
                </div>
                <button
                  onClick={() => setIsCreateModalOpen(false)}
                  className="p-1.5 rounded-lg text-zinc-400 hover:text-foreground hover:bg-white/5"
                >
                  <X size={18} />
                </button>
              </div>

              <form onSubmit={handleCreateSkillSubmit} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-semibold text-zinc-300 block mb-1.5">Nome da Skill</label>
                    <input
                      type="text"
                      required
                      placeholder="Ex: Qualificação BANT Avançada"
                      value={newSkillName}
                      onChange={e => setNewSkillName(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    />
                  </div>

                  <div>
                    <label className="text-xs font-semibold text-zinc-300 block mb-1.5">Categoria</label>
                    <select
                      value={newSkillCategory}
                      onChange={e => setNewSkillCategory(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    >
                      <option value="vendas">Vendas & SDR</option>
                      <option value="atendimento">Atendimento Geral</option>
                      <option value="suporte">Suporte Técnico</option>
                      <option value="automacao">Automação & CRM</option>
                      <option value="geral">Geral</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="text-xs font-semibold text-zinc-300 block mb-1.5">Descrição Curta</label>
                  <textarea
                    rows={2}
                    required
                    placeholder="Descreva o propósito da skill em 1 ou 2 frases para que o modelo entenda quando ativá-la..."
                    value={newSkillDesc}
                    onChange={e => setNewSkillDesc(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50 resize-none"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-zinc-300 block mb-1.5">Tags da Skill</label>
                  <div className="flex items-center gap-2 mb-2">
                    <input
                      type="text"
                      placeholder="Adicione uma tag (pressione Enter)..."
                      value={newSkillTagInput}
                      onChange={e => setNewSkillTagInput(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          handleAddTag();
                        }
                      }}
                      className="flex-1 px-3.5 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50 font-mono"
                    />
                    <button
                      type="button"
                      onClick={handleAddTag}
                      className="px-3.5 py-2 rounded-xl bg-zinc-800 text-zinc-200 text-xs font-medium hover:bg-zinc-700"
                    >
                      Adicionar
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {newSkillTags.map(tag => (
                      <span
                        key={tag}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-zinc-800 text-zinc-300 text-[11px] font-mono border border-zinc-700/60"
                      >
                        #{tag}
                        <button
                          type="button"
                          onClick={() => setNewSkillTags(newSkillTags.filter(t => t !== tag))}
                          className="hover:text-red-400 ml-0.5"
                        >
                          <X size={11} />
                        </button>
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-semibold text-zinc-300">Conteúdo do Arquivo SKILL.md</label>
                    <span className="text-[10px] text-zinc-500 font-mono">Markdown</span>
                  </div>
                  <textarea
                    rows={8}
                    required
                    value={newSkillContent}
                    onChange={e => setNewSkillContent(e.target.value)}
                    className="w-full p-3.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground font-mono focus:outline-none focus:border-primary/50 resize-y leading-relaxed"
                  />
                </div>

                <div className="flex items-center justify-end gap-3 pt-4 border-t border-zinc-800/80">
                  <button
                    type="button"
                    onClick={() => setIsCreateModalOpen(false)}
                    className="px-4 py-2.5 rounded-xl text-xs font-medium text-zinc-400 hover:text-foreground hover:bg-white/5 cursor-pointer transition-colors"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="px-5 py-2.5 rounded-xl bg-primary text-primary-foreground text-xs font-semibold shadow-lg shadow-primary/20 hover:bg-primary/90 cursor-pointer transition-all disabled:opacity-50"
                  >
                    {isSubmitting ? 'Criando...' : 'Salvar & Instalar Skill'}
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
