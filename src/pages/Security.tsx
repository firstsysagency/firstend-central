import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  Plus,
  FileCode,
  FileText,
  CheckCircle2,
  Trash2,
  Copy,
  Check,
  X,
  FolderOpen,
  Save,
  History,
  LayoutGrid,
  Table as TableIcon,
  Eye,
  Code2,
  Lock,
  FileCheck,
  AlertTriangle,
  Info
} from 'lucide-react';
import type {
  SecurityItem,
  SecurityFile,
  SecurityAuditLog,
  SecurityCategory,
  SecuritySeverity
} from '../types/security';

const CATEGORIES: { id: string; label: string }[] = [
  { id: 'todas', label: 'Todos os Métodos' },
  { id: 'hardening', label: 'Hardening & Headers' },
  { id: 'autenticacao', label: 'Autenticação & MFA' },
  { id: 'criptografia', label: 'Criptografia & Cofre' },
  { id: 'banco_de_dados', label: 'Banco de Dados & RLS' },
  { id: 'conformidade', label: 'Conformidade & LGPD' },
  { id: 'rede_api', label: 'Rede & Anti-SSRF' },
  { id: 'auditoria', label: 'Auditoria & Logs' }
];

const SEVERITIES: { id: string; label: string; color: string }[] = [
  { id: 'todas', label: 'Todas as Severidades', color: 'zinc' },
  { id: 'critico', label: 'Crítico', color: 'rose' },
  { id: 'alto', label: 'Alto', color: 'amber' },
  { id: 'medio', label: 'Médio', color: 'blue' },
  { id: 'baixo', label: 'Baixo', color: 'emerald' },
  { id: 'informativo', label: 'Informativo', color: 'purple' }
];

export default function Security() {
  const [items, setItems] = useState<SecurityItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('todas');
  const [selectedSeverity, setSelectedSeverity] = useState('todas');
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Gestão dinâmica de tags nos cards
  const [addingTagItemId, setAddingTagItemId] = useState<string | null>(null);
  const [newTagInput, setNewTagInput] = useState('');

  // Modal de Detalhes do Método de Segurança
  const [selectedItem, setSelectedItem] = useState<SecurityItem | null>(null);
  const [activeModalTab, setActiveModalTab] = useState<'files' | 'audit'>('files');
  const [activeFilePath, setActiveFilePath] = useState<string>('SECURITY.md');
  const [fileContentEditor, setFileContentEditor] = useState<string>('');
  const [previewMode, setPreviewMode] = useState<'edit' | 'preview'>('edit');
  const [isSavingFile, setIsSavingFile] = useState(false);
  const [copiedFile, setCopiedFile] = useState(false);
  const [auditLogsList, setAuditLogsList] = useState<SecurityAuditLog[]>([]);

  // Modal de Novo Arquivo Técnico
  const [isAddFileModalOpen, setIsAddFileModalOpen] = useState(false);
  const [newFilePath, setNewFilePath] = useState('');
  const [newFileContent, setNewFileContent] = useState('');

  // Modal de Cadastro de Nova Tecnologia de Segurança
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newDetailedDesc, setNewDetailedDesc] = useState('');
  const [newCategory, setNewCategory] = useState<SecurityCategory>('hardening');
  const [newSeverity, setNewSeverity] = useState<SecuritySeverity>('alto');
  const [newCompliance, setNewCompliance] = useState('LGPD, OWASP Top 10');
  const [newTags, setNewTags] = useState('seguranca, hardening');
  const [newContent, setNewContent] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Carregar catálogo de segurança do backend
  const loadSecurityItems = async () => {
    try {
      setIsLoading(true);
      const res = await fetch('/api/security');
      if (res.ok) {
        const data = await res.json();
        setItems(data.items || []);
      }
    } catch (err) {
      console.error('Erro ao carregar catálogo de segurança:', err);
      showToast('Falha na comunicação com o servidor de segurança.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSecurityItems();
  }, []);

  // Filtragem de itens
  const filteredItems = useMemo(() => {
    return items.filter(item => {
      const matchesCat = selectedCategory === 'todas' || item.category === selectedCategory;
      const matchesSev = selectedSeverity === 'todas' || item.severity === selectedSeverity;
      const q = searchTerm.toLowerCase().trim();
      const matchesSearch =
        !q ||
        item.name.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q) ||
        item.slug.toLowerCase().includes(q) ||
        (item.tags || []).some(t => t.toLowerCase().includes(q)) ||
        (item.complianceStandards || []).some(c => c.toLowerCase().includes(q));

      return matchesCat && matchesSev && matchesSearch;
    });
  }, [items, selectedCategory, selectedSeverity, searchTerm]);

  // Adicionar Tag Dinâmica
  const handleAddTag = async (itemId: string, rawTag: string) => {
    const clean = rawTag.trim().replace(/^#/, '');
    if (!clean) return;

    try {
      const res = await fetch(`/api/security/${itemId}/tags`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tag: clean })
      });

      if (res.ok) {
        const data = await res.json();
        setItems(prev => prev.map(i => (i.id === itemId ? { ...i, tags: data.tags } : i)));
        if (selectedItem?.id === itemId) {
          setSelectedItem(prev => (prev ? { ...prev, tags: data.tags } : null));
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
  const handleRemoveTag = async (itemId: string, tag: string) => {
    try {
      const res = await fetch(`/api/security/${itemId}/tags/${encodeURIComponent(tag)}`, {
        method: 'DELETE'
      });

      if (res.ok) {
        const data = await res.json();
        setItems(prev => prev.map(i => (i.id === itemId ? { ...i, tags: data.tags } : i)));
        if (selectedItem?.id === itemId) {
          setSelectedItem(prev => (prev ? { ...prev, tags: data.tags } : null));
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

  // Abrir Modal de Detalhes
  const handleOpenItemDetails = async (item: SecurityItem) => {
    setSelectedItem(item);
    setActiveModalTab('files');
    setActiveFilePath('SECURITY.md');
    setPreviewMode('edit');

    const secFile = (item.files || []).find(f => f.path.toLowerCase() === 'security.md' && !f.deletedAt) || item.files?.[0];
    if (secFile) {
      setActiveFilePath(secFile.path);
      setFileContentEditor(secFile.content || '');
    } else {
      setFileContentEditor('# ' + item.name + '\n\nDiretrizes de segurança corporativa.');
    }

    try {
      const res = await fetch(`/api/security/${item.id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedItem(data.item);
        setAuditLogsList(data.auditLogs || []);
      }
    } catch (e) {
      console.warn('Erro ao carregar auditoria detalhada:', e);
    }
  };

  // Selecionar arquivo para edição/visualização
  const handleSelectFile = (file: SecurityFile) => {
    setActiveFilePath(file.path);
    setFileContentEditor(file.content || '');
  };

  // Salvar alterações no arquivo
  const handleSaveFileContent = async () => {
    if (!selectedItem || !activeFilePath) return;

    try {
      setIsSavingFile(true);
      const res = await fetch(`/api/security/${selectedItem.id}/files`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: activeFilePath,
          content: fileContentEditor
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedItem(data.securityItem);
        setItems(prev => prev.map(i => (i.id === data.securityItem.id ? data.securityItem : i)));
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

  // Criar Novo Arquivo Técnico
  const handleCreateFileSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedItem || !newFilePath.trim()) return;

    try {
      const res = await fetch(`/api/security/${selectedItem.id}/files`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: newFilePath.trim(),
          content: newFileContent.trim() || `# ${newFilePath.trim()}\n\nConteúdo técnico.`
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedItem(data.securityItem);
        setItems(prev => prev.map(i => (i.id === data.securityItem.id ? data.securityItem : i)));
        setActiveFilePath(newFilePath.trim());
        setFileContentEditor(newFileContent.trim() || `# ${newFilePath.trim()}\n\nConteúdo técnico.`);
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

  // Excluir Arquivo Técnico
  const handleDeleteFile = async (filePath: string) => {
    if (!selectedItem) return;
    if (filePath.toLowerCase() === 'security.md') {
      showToast('O arquivo mestre "SECURITY.md" não pode ser excluído.');
      return;
    }

    if (!window.confirm(`Deseja realmente remover o arquivo "${filePath}"?`)) return;

    try {
      const res = await fetch(`/api/security/${selectedItem.id}/files/${encodeURIComponent(filePath)}`, {
        method: 'DELETE'
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedItem(data.securityItem);
        setItems(prev => prev.map(i => (i.id === data.securityItem.id ? data.securityItem : i)));
        const fallback = (data.securityItem.files || []).find((f: any) => !f.deletedAt);
        if (fallback) {
          setActiveFilePath(fallback.path);
          setFileContentEditor(fallback.content || '');
        }
        showToast(`Arquivo "${filePath}" removido com sucesso.`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao excluir arquivo.');
      }
    } catch {
      showToast('Erro ao excluir arquivo.');
    }
  };

  // Submeter cadastro de nova tecnologia de segurança
  const handleCreateSecuritySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) {
      showToast('Informe o nome da tecnologia de segurança.');
      return;
    }

    try {
      setIsSubmitting(true);
      const complianceList = newCompliance
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);

      const tagList = newTags
        .split(',')
        .map(s => s.trim().toLowerCase().replace(/^#/, ''))
        .filter(Boolean);

      const res = await fetch('/api/security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newName.trim(),
          description: newDesc.trim() || 'Diretriz técnica de segurança corporativa.',
          detailedDescription: newDetailedDesc.trim(),
          category: newCategory,
          severity: newSeverity,
          complianceStandards: complianceList,
          tags: tagList,
          initialContent: newContent.trim() || `# ${newName.trim()}\n\n## 1. Visão Geral e Arquitetura\nDescreva os requisitos técnicos de segurança.\n\n## 2. Regras e Controles\n- Defina as políticas obrigatórias.`
        })
      });

      if (res.ok) {
        const data = await res.json();
        setItems(prev => [data.item, ...prev]);
        setIsCreateModalOpen(false);
        setNewName('');
        setNewDesc('');
        setNewDetailedDesc('');
        setNewContent('');
        showToast(`Padrão "${data.item.name}" cadastrado com sucesso!`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao cadastrar padrão de segurança.');
      }
    } catch {
      showToast('Erro de conexão ao criar método de segurança.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Copiar conteúdo para o clipboard
  const handleCopyFileContent = () => {
    navigator.clipboard.writeText(fileContentEditor);
    setCopiedFile(true);
    setTimeout(() => setCopiedFile(false), 2000);
    showToast('Conteúdo copiado para a área de transferência.');
  };

  // Renderizador seguro e leve de Markdown
  const renderMarkdownPreview = (text: string) => {
    const lines = text.split('\n');
    return (
      <div className="space-y-3 font-sans text-xs leading-relaxed text-zinc-300">
        {lines.map((line, idx) => {
          if (line.startsWith('### ')) {
            return <h4 key={idx} className="text-sm font-bold text-foreground mt-4 mb-2">{line.replace('### ', '')}</h4>;
          }
          if (line.startsWith('## ')) {
            return <h3 key={idx} className="text-base font-extrabold text-foreground mt-6 mb-2 pb-1 border-b border-zinc-800">{line.replace('## ', '')}</h3>;
          }
          if (line.startsWith('# ')) {
            return <h2 key={idx} className="text-lg font-black text-primary mt-6 mb-3 pb-2 border-b border-primary/20">{line.replace('# ', '')}</h2>;
          }
          if (line.startsWith('- [ ] ') || line.startsWith('- [x] ')) {
            const isChecked = line.startsWith('- [x] ');
            return (
              <div key={idx} className="flex items-center gap-2 pl-2 py-0.5">
                <input type="checkbox" readOnly checked={isChecked} className="rounded accent-primary" />
                <span className={isChecked ? 'line-through text-zinc-500' : 'text-zinc-300'}>{line.substring(6)}</span>
              </div>
            );
          }
          if (line.startsWith('- ') || line.startsWith('* ')) {
            return (
              <div key={idx} className="flex items-start gap-2 pl-3">
                <span className="text-primary mt-1">•</span>
                <span>{line.substring(2)}</span>
              </div>
            );
          }
          if (line.startsWith('```')) {
            return <div key={idx} className="font-mono text-[11px] bg-zinc-950 p-2.5 rounded-lg border border-zinc-800 text-zinc-400 overflow-x-auto my-2">{line}</div>;
          }
          if (line.trim() === '') {
            return <div key={idx} className="h-2" />;
          }
          return <p key={idx} className="leading-relaxed">{line}</p>;
        })}
      </div>
    );
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Toast Flutuante com Framer Motion */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            className="fixed top-6 right-6 z-50 flex items-center gap-3 px-5 py-3.5 rounded-xl bg-zinc-900 border border-primary/40 text-foreground shadow-2xl backdrop-blur-md"
          >
            <ShieldCheck className="text-primary w-5 h-5 flex-shrink-0 animate-pulse" />
            <span className="text-sm font-medium">{toastMessage}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Hero Header Corporativo de Segurança */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-zinc-900/95 via-zinc-900/60 to-zinc-950 p-8 border border-zinc-800/80 shadow-2xl backdrop-blur-xl">
        <div className="absolute -right-16 -top-16 w-80 h-80 bg-rose-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -left-16 -bottom-16 w-80 h-80 bg-primary/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-semibold tracking-wide">
              <ShieldCheck size={14} />
              Biblioteca Corporativa de Segurança, Hardening & IA Firstsys
            </div>
            <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-foreground">
              Segurança & Governança
            </h1>
            <p className="text-sm md:text-base text-zinc-400 max-w-2xl leading-relaxed">
              Catálogo corporativo de playbooks técnicos, métodos de criptografia, sanitização e checklists de conformidade 
              para projetos de engenharia e agentes de IA conectados ao protocolo MCP.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => {
                setNewContent(`# Novo Padrão de Segurança\n\n## 1. Visão Geral\nDescreva a ameaça mitigada e o escopo.\n\n## 2. Regras e Controles Mandatórios\n- Implemente proteção no gateway.\n- Valide parâmetros de entrada.`);
                setIsCreateModalOpen(true);
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary text-primary-foreground font-semibold shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-all duration-300 hover:scale-[1.02] cursor-pointer text-xs"
            >
              <Plus size={16} />
              Cadastrar Método de Segurança
            </button>
          </div>
        </div>

        {/* Resumo de Métricas de Segurança */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8 pt-6 border-t border-zinc-800/60">
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Métodos Registrados</span>
            <p className="text-2xl font-bold text-foreground">{items.length}</p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Severidade Crítica/Alta</span>
            <p className="text-2xl font-bold text-rose-400">
              {items.filter(i => i.severity === 'critico' || i.severity === 'alto').length}
            </p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Conformidade Ativa</span>
            <p className="text-2xl font-bold text-emerald-400 flex items-center gap-1.5">
              <FileCheck size={18} />
              LGPD / OWASP
            </p>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Protocolo MCP</span>
            <p className="text-2xl font-bold text-primary flex items-center gap-1.5">
              <CheckCircle2 size={18} className="text-emerald-400" />
              13 Tools Integradas
            </p>
          </div>
        </div>
      </div>

      {/* Barra de Filtros por Categoria e Severidade */}
      <div className="space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Abas de Categorias com Framer Motion layoutId */}
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
                      layoutId="security-category-tab"
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
                placeholder="Buscar por nome, tag ou norma (LGPD, OWASP)..."
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
                className={`p-1.5 rounded-lg text-xs transition-colors cursor-pointer ${
                  viewMode === 'cards' ? 'bg-zinc-800 text-primary' : 'text-zinc-400 hover:text-zinc-200'
                }`}
                title="Visualização em Cards"
              >
                <LayoutGrid size={16} />
              </button>
              <button
                onClick={() => setViewMode('table')}
                className={`p-1.5 rounded-lg text-xs transition-colors cursor-pointer ${
                  viewMode === 'table' ? 'bg-zinc-800 text-primary' : 'text-zinc-400 hover:text-zinc-200'
                }`}
                title="Visualização em Tabela"
              >
                <TableIcon size={16} />
              </button>
            </div>
          </div>
        </div>

        {/* Filtro Secundário por Severidade */}
        <div className="flex items-center gap-2 overflow-x-auto text-xs text-zinc-400">
          <span className="font-medium text-zinc-500">Severidade:</span>
          {SEVERITIES.map(sev => (
            <button
              key={sev.id}
              onClick={() => setSelectedSeverity(sev.id)}
              className={`px-2.5 py-1 rounded-lg border text-xs cursor-pointer transition-all ${
                selectedSeverity === sev.id
                  ? 'bg-zinc-800 border-primary/40 text-primary font-medium'
                  : 'bg-zinc-900/50 border-zinc-800/80 text-zinc-400 hover:text-zinc-300'
              }`}
            >
              {sev.label}
            </button>
          ))}
        </div>
      </div>

      {/* Grid de Cards ou Tabela */}
      {isLoading ? (
        <div className="py-20 flex flex-col items-center justify-center gap-4 text-zinc-500">
          <div className="w-10 h-10 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
          <p className="text-xs uppercase tracking-widest font-mono">Carregando Biblioteca de Segurança...</p>
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="py-16 text-center rounded-2xl border border-dashed border-zinc-800 bg-zinc-950/40 p-8">
          <ShieldAlert size={40} className="mx-auto text-zinc-600 mb-3" />
          <h3 className="text-base font-semibold text-foreground">Nenhum método de segurança encontrado</h3>
          <p className="text-xs text-zinc-500 mt-1 max-w-md mx-auto">
            Tente alterar o termo de pesquisa, o filtro de severidade ou cadastre uma nova tecnologia de segurança.
          </p>
        </div>
      ) : viewMode === 'cards' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredItems.map(item => {
            const fileCount = (item.files || []).filter(f => !f.deletedAt).length;

            return (
              <motion.div
                key={item.id}
                layout
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.2 }}
                className="group relative flex flex-col justify-between rounded-2xl bg-zinc-900/60 border border-zinc-800/80 hover:border-zinc-700/80 p-6 shadow-xl backdrop-blur-md transition-all duration-300 hover:shadow-2xl hover:-translate-y-1"
              >
                <div>
                  {/* Badges Superiores */}
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-300 border border-zinc-700/60">
                      {item.category}
                    </span>
                    <div className="flex items-center gap-1.5">
                      {item.severity === 'critico' ? (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-rose-950/60 text-rose-400 border border-rose-800/60 font-semibold">
                          <AlertTriangle size={10} /> Crítico
                        </span>
                      ) : item.severity === 'alto' ? (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-amber-950/60 text-amber-400 border border-amber-800/60 font-semibold">
                          <ShieldAlert size={10} /> Alto
                        </span>
                      ) : item.severity === 'medio' ? (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-blue-950/60 text-blue-400 border border-blue-800/60">
                          <ShieldCheck size={10} /> Médio
                        </span>
                      ) : item.severity === 'baixo' ? (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                          <Check size={10} /> Baixo
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-purple-950/60 text-purple-400 border border-purple-800/60">
                          <Info size={10} /> Info
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Nome e Descrição */}
                  <h3 className="text-lg font-bold text-foreground group-hover:text-primary transition-colors">
                    {item.name}
                  </h3>
                  <p className="text-xs text-zinc-400 mt-2 line-clamp-3 leading-relaxed">
                    {item.description}
                  </p>

                  {/* Badges de Normas de Conformidade */}
                  {item.complianceStandards && item.complianceStandards.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 mt-3.5">
                      {item.complianceStandards.map(comp => (
                        <span key={comp} className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/40 font-mono">
                          {comp}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Tags Dinâmicas com Adição e Remoção */}
                  <div className="flex flex-wrap items-center gap-1.5 mt-3.5">
                    {item.tags.map(tag => (
                      <span
                        key={tag}
                        className="group/tag inline-flex items-center gap-1 text-[10px] pl-2 pr-1.5 py-0.5 rounded-md bg-zinc-800/80 text-zinc-300 font-mono border border-zinc-700/60 hover:border-zinc-500 transition-colors"
                      >
                        <span>#{tag}</span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRemoveTag(item.id, tag);
                          }}
                          className="text-zinc-500 hover:text-rose-400 p-0.5 rounded transition-colors cursor-pointer"
                          title={`Remover tag #${tag}`}
                        >
                          <X size={10} />
                        </button>
                      </span>
                    ))}

                    {addingTagItemId === item.id ? (
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
                              handleAddTag(item.id, newTagInput);
                              setNewTagInput('');
                              setAddingTagItemId(null);
                            } else if (e.key === 'Escape') {
                              setAddingTagItemId(null);
                              setNewTagInput('');
                            }
                          }}
                          className="w-20 bg-transparent text-[10px] text-zinc-200 outline-none font-mono"
                        />
                        <button
                          type="button"
                          onClick={() => {
                            handleAddTag(item.id, newTagInput);
                            setNewTagInput('');
                            setAddingTagItemId(null);
                          }}
                          className="text-emerald-400 hover:text-emerald-300 cursor-pointer"
                          title="Confirmar"
                        >
                          <Check size={11} />
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setAddingTagItemId(null);
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
                          setAddingTagItemId(item.id);
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
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleOpenItemDetails(item)}
                      className="px-3.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium cursor-pointer transition-colors"
                    >
                      Abrir Diretrizes & Arquivos
                    </button>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      ) : (
        /* Visualização em Tabela */
        <div className="overflow-x-auto rounded-2xl border border-zinc-800 bg-zinc-900/60 backdrop-blur-md shadow-xl">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-900/90 text-zinc-400 uppercase text-[10px] tracking-wider border-b border-zinc-800">
              <tr>
                <th className="py-3 px-4">Método de Segurança</th>
                <th className="py-3 px-4">Categoria</th>
                <th className="py-3 px-4">Severidade</th>
                <th className="py-3 px-4">Conformidade</th>
                <th className="py-3 px-4">Arquivos</th>
                <th className="py-3 px-4 text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {filteredItems.map(item => (
                <tr key={item.id} className="hover:bg-zinc-800/30 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-semibold text-foreground">{item.name}</div>
                    <div className="text-[10px] font-mono text-zinc-500">{item.slug}</div>
                  </td>
                  <td className="py-3 px-4 text-zinc-400 capitalize">{item.category}</td>
                  <td className="py-3 px-4">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium capitalize ${
                      item.severity === 'critico' ? 'bg-rose-950 text-rose-400 border border-rose-800/60' :
                      item.severity === 'alto' ? 'bg-amber-950 text-amber-400 border border-amber-800/60' :
                      item.severity === 'medio' ? 'bg-blue-950 text-blue-400 border border-blue-800/60' :
                      'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                    }`}>
                      {item.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-zinc-400">
                    {(item.complianceStandards || []).join(', ') || '-'}
                  </td>
                  <td className="py-3 px-4 text-zinc-400">{item.files?.length || 0}</td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => handleOpenItemDetails(item)}
                      className="px-2.5 py-1 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs cursor-pointer"
                    >
                      Detalhes
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL COMPLETO DE GERENCIAMENTO DE ARQUIVOS E AUDITORIA */}
      {/* ==================================================================== */}
      <AnimatePresence>
        {selectedItem && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              className="relative w-full max-w-5xl h-[85vh] flex flex-col rounded-3xl bg-zinc-950 border border-zinc-800 shadow-2xl overflow-hidden"
            >
              {/* Header do Modal */}
              <div className="p-6 border-b border-zinc-800/80 bg-zinc-900/60 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                    <ShieldCheck size={20} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-xl font-bold text-foreground">{selectedItem.name}</h2>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-300">
                        {selectedItem.category}
                      </span>
                    </div>
                    <p className="text-xs text-zinc-400 mt-0.5">{selectedItem.description}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setSelectedItem(null)}
                    className="p-2 rounded-xl text-zinc-400 hover:text-foreground hover:bg-white/5 cursor-pointer"
                    title="Fechar modal"
                  >
                    <X size={18} />
                  </button>
                </div>
              </div>

              {/* Sub-abas do Modal */}
              <div className="px-6 py-2.5 border-b border-zinc-800/60 bg-zinc-900/40 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setActiveModalTab('files')}
                    className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
                      activeModalTab === 'files' ? 'bg-primary text-primary-foreground' : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    <FileCode size={14} />
                    Arquivos Técnicos ({selectedItem.files?.length || 0})
                  </button>
                  <button
                    onClick={() => setActiveModalTab('audit')}
                    className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
                      activeModalTab === 'audit' ? 'bg-primary text-primary-foreground' : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    <History size={14} />
                    Trilha de Auditoria ({auditLogsList.length})
                  </button>
                </div>

                {activeModalTab === 'files' && (
                  <div className="flex items-center gap-2">
                    <div className="flex items-center bg-zinc-900 rounded-lg p-0.5 border border-zinc-800 text-xs">
                      <button
                        onClick={() => setPreviewMode('edit')}
                        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-colors ${
                          previewMode === 'edit' ? 'bg-zinc-800 text-primary font-medium' : 'text-zinc-400 hover:text-zinc-200'
                        }`}
                      >
                        <Code2 size={13} />
                        Código
                      </button>
                      <button
                        onClick={() => setPreviewMode('preview')}
                        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-colors ${
                          previewMode === 'preview' ? 'bg-zinc-800 text-primary font-medium' : 'text-zinc-400 hover:text-zinc-200'
                        }`}
                      >
                        <Eye size={13} />
                        Markdown
                      </button>
                    </div>

                    <button
                      onClick={handleCopyFileContent}
                      className="p-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-zinc-200 text-xs flex items-center gap-1 cursor-pointer"
                      title="Copiar conteúdo"
                    >
                      {copiedFile ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                    </button>

                    <button
                      onClick={handleSaveFileContent}
                      disabled={isSavingFile}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-semibold cursor-pointer transition-all shadow-md shadow-primary/20"
                    >
                      <Save size={13} />
                      {isSavingFile ? 'Salvando...' : 'Salvar Alterações'}
                    </button>
                  </div>
                )}
              </div>

              {/* Corpo Principal do Modal */}
              <div className="flex-1 flex overflow-hidden">
                {activeModalTab === 'files' ? (
                  <>
                    {/* Árvore Lateral de Arquivos */}
                    <div className="w-64 border-r border-zinc-800/80 bg-zinc-950 p-4 flex flex-col justify-between overflow-y-auto">
                      <div className="space-y-3">
                        <div className="flex items-center justify-between text-xs text-zinc-400 font-semibold uppercase tracking-wider px-1">
                          <span>Arquivos</span>
                          <button
                            onClick={() => setIsAddFileModalOpen(true)}
                            className="p-1 rounded-md hover:bg-zinc-800 text-zinc-400 hover:text-primary cursor-pointer transition-colors"
                            title="Criar novo arquivo"
                          >
                            <Plus size={14} />
                          </button>
                        </div>

                        <div className="space-y-1">
                          {(selectedItem.files || [])
                            .filter(f => !f.deletedAt)
                            .map(file => {
                              const isActive = activeFilePath === file.path;
                              const isSecurityMd = file.path.toLowerCase() === 'security.md';

                              return (
                                <div
                                  key={file.id || file.path}
                                  onClick={() => handleSelectFile(file)}
                                  className={`group flex items-center justify-between px-3 py-2 rounded-xl text-xs font-mono cursor-pointer transition-colors ${
                                    isActive
                                      ? 'bg-primary/10 border border-primary/30 text-primary font-bold'
                                      : 'hover:bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-transparent'
                                  }`}
                                >
                                  <div className="flex items-center gap-2 overflow-hidden text-ellipsis whitespace-nowrap">
                                    {isSecurityMd ? (
                                      <Lock size={13} className="text-primary flex-shrink-0" />
                                    ) : file.extension === '.json' ? (
                                      <FileCode size={13} className="text-cyan-400 flex-shrink-0" />
                                    ) : (
                                      <FileText size={13} className="text-zinc-400 flex-shrink-0" />
                                    )}
                                    <span className="truncate">{file.path}</span>
                                  </div>

                                  {!isSecurityMd && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleDeleteFile(file.path);
                                      }}
                                      className="opacity-0 group-hover:opacity-100 p-1 hover:text-rose-400 transition-opacity"
                                      title="Excluir arquivo"
                                    >
                                      <Trash2 size={12} />
                                    </button>
                                  )}
                                </div>
                              );
                            })}
                        </div>
                      </div>

                      <div className="pt-4 border-t border-zinc-900 text-[10px] text-zinc-500 font-mono">
                        Arquivo: {activeFilePath}
                      </div>
                    </div>

                    {/* Editor / Visualizador Markdown */}
                    <div className="flex-1 bg-zinc-900/30 p-6 overflow-y-auto">
                      {previewMode === 'edit' ? (
                        <textarea
                          value={fileContentEditor}
                          onChange={e => setFileContentEditor(e.target.value)}
                          className="w-full h-full min-h-[500px] bg-transparent text-zinc-200 font-mono text-xs leading-relaxed focus:outline-none resize-none"
                          placeholder="Digite as instruções e diretrizes de segurança..."
                        />
                      ) : (
                        <div className="max-w-3xl mx-auto py-2">
                          {renderMarkdownPreview(fileContentEditor)}
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  /* Aba de Auditoria */
                  <div className="flex-1 p-6 overflow-y-auto bg-zinc-950">
                    <h3 className="text-sm font-bold text-foreground mb-4 flex items-center gap-2">
                      <History size={16} className="text-primary" />
                      Trilha de Auditoria e Alterações Técnicas
                    </h3>

                    {auditLogsList.length === 0 ? (
                      <p className="text-xs text-zinc-500">Nenhum registro de auditoria disponível.</p>
                    ) : (
                      <div className="space-y-3">
                        {auditLogsList.map(log => (
                          <div
                            key={log.id}
                            className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 text-xs space-y-1"
                          >
                            <div className="flex items-center justify-between text-zinc-400">
                              <span className="font-semibold text-primary">{log.action}</span>
                              <span className="font-mono text-[10px]">
                                {new Date(log.createdAt).toLocaleString('pt-BR')}
                              </span>
                            </div>
                            <p className="text-zinc-300">{log.details}</p>
                            <span className="text-[10px] font-mono text-zinc-500 block">Autor: {log.actor}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Modal de Adicionar Novo Arquivo */}
      <AnimatePresence>
        {isAddFileModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-md rounded-2xl bg-zinc-950 border border-zinc-800 p-6 shadow-2xl space-y-4"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-base font-bold text-foreground">Novo Arquivo Técnico</h3>
                <button
                  onClick={() => setIsAddFileModalOpen(false)}
                  className="p-1 rounded-lg text-zinc-400 hover:text-foreground"
                >
                  <X size={16} />
                </button>
              </div>

              <form onSubmit={handleCreateFileSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-zinc-400 mb-1">
                    Caminho Relativo (ex: rules.json, checklist.md)
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="checklist.md"
                    value={newFilePath}
                    onChange={e => setNewFilePath(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-400 mb-1">
                    Conteúdo Inicial
                  </label>
                  <textarea
                    rows={4}
                    placeholder="# Conteúdo inicial do arquivo..."
                    value={newFileContent}
                    onChange={e => setNewFileContent(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50 font-mono"
                  />
                </div>

                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsAddFileModalOpen(false)}
                    className="px-4 py-2 rounded-xl bg-zinc-800 text-zinc-300 text-xs font-medium"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 rounded-xl bg-primary text-primary-foreground text-xs font-semibold"
                  >
                    Criar Arquivo
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Modal de Cadastrar Nova Tecnologia de Segurança */}
      <AnimatePresence>
        {isCreateModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-3xl bg-zinc-950 border border-zinc-800 p-6 sm:p-8 shadow-2xl space-y-6"
            >
              <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                    <ShieldCheck size={20} />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-foreground">Cadastrar Tecnologia de Segurança</h3>
                    <p className="text-xs text-zinc-400">Adicione uma nova diretriz técnica à biblioteca corporativa.</p>
                  </div>
                </div>
                <button
                  onClick={() => setIsCreateModalOpen(false)}
                  className="p-1 rounded-lg text-zinc-400 hover:text-foreground cursor-pointer"
                >
                  <X size={18} />
                </button>
              </div>

              <form onSubmit={handleCreateSecuritySubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-zinc-400 mb-1">
                    Nome da Tecnologia / Método
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="Hardening de Headers HTTP e Helmet"
                    value={newName}
                    onChange={e => setNewName(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1">Categoria Técnica</label>
                    <select
                      value={newCategory}
                      onChange={e => setNewCategory(e.target.value as any)}
                      className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    >
                      <option value="hardening">Hardening & Headers</option>
                      <option value="autenticacao">Autenticação & MFA</option>
                      <option value="criptografia">Criptografia & Cofre</option>
                      <option value="banco_de_dados">Banco de Dados & RLS</option>
                      <option value="conformidade">Conformidade & LGPD</option>
                      <option value="rede_api">Rede & Anti-SSRF</option>
                      <option value="auditoria">Auditoria & Logs</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1">Nível de Severidade</label>
                    <select
                      value={newSeverity}
                      onChange={e => setNewSeverity(e.target.value as any)}
                      className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    >
                      <option value="critico">Crítico</option>
                      <option value="alto">Alto</option>
                      <option value="medio">Médio</option>
                      <option value="baixo">Baixo</option>
                      <option value="informativo">Informativo</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-400 mb-1">Resumo Executivo</label>
                  <textarea
                    rows={2}
                    required
                    placeholder="Explicação concisa do objetivo desta segurança..."
                    value={newDesc}
                    onChange={e => setNewDesc(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1">
                      Normas de Conformidade (separadas por vírgula)
                    </label>
                    <input
                      type="text"
                      placeholder="LGPD, OWASP Top 10, NIST"
                      value={newCompliance}
                      onChange={e => setNewCompliance(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1">
                      Tags de Indexação (separadas por vírgula)
                    </label>
                    <input
                      type="text"
                      placeholder="node, express, seguranca"
                      value={newTags}
                      onChange={e => setNewTags(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-400 mb-1">
                    Conteúdo Inicial do SECURITY.md
                  </label>
                  <textarea
                    rows={6}
                    value={newContent}
                    onChange={e => setNewContent(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground font-mono focus:outline-none focus:border-primary/50 leading-relaxed"
                  />
                </div>

                <div className="flex items-center justify-end gap-3 pt-4 border-t border-zinc-800">
                  <button
                    type="button"
                    onClick={() => setIsCreateModalOpen(false)}
                    className="px-4 py-2.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-semibold cursor-pointer"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="px-5 py-2.5 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-bold shadow-lg shadow-primary/20 cursor-pointer"
                  >
                    {isSubmitting ? 'Cadastrando...' : 'Cadastrar Padrão'}
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
