import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  Plus,
  FileText,
  Trash2,
  Copy,
  Check,
  X,
  Save,
  LayoutGrid,
  Table as TableIcon,
  Eye,
  Code2,
  AlertTriangle,
  Info
} from 'lucide-react';
import type {
  SecurityItem,
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

  // Modal de Consulta e Edição do Documento Explicativo
  const [selectedItem, setSelectedItem] = useState<SecurityItem | null>(null);
  const [documentEditorContent, setDocumentEditorContent] = useState<string>('');
  const [previewMode, setPreviewMode] = useState<'preview' | 'edit'>('preview');
  const [isSavingDocument, setIsSavingDocument] = useState(false);
  const [copiedDocument, setCopiedDocument] = useState(false);
  const [copiedItemId, setCopiedItemId] = useState<string | null>(null);

  // Modal de Criação de Novo Padrão de Segurança
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newCategory, setNewCategory] = useState<SecurityCategory>('hardening');
  const [newSeverity, setNewSeverity] = useState<SecuritySeverity>('alto');
  const [newCompliance, setNewCompliance] = useState('LGPD, OWASP Top 10');
  const [newTags, setNewTags] = useState('seguranca, hardening');
  const [newDocumentContent, setNewDocumentContent] = useState('');
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
        (item.content && item.content.toLowerCase().includes(q)) ||
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
        showToast(`Tag "#${clean}" adicionada.`);
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

  // Abrir Modal de Consulta do Documento
  const handleOpenItemDetails = (item: SecurityItem, initialMode: 'preview' | 'edit' = 'preview') => {
    setSelectedItem(item);
    setPreviewMode(initialMode);
    const content = item.content || (item.files?.[0]?.content) || item.description || `# ${item.name}\n\nDiretrizes de segurança.`;
    setDocumentEditorContent(content);
  };

  // Salvar alterações no Documento Explicativo
  const handleSaveDocumentContent = async () => {
    if (!selectedItem) return;

    try {
      setIsSavingDocument(true);
      const res = await fetch(`/api/security/${selectedItem.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: documentEditorContent
        })
      });

      if (res.ok) {
        const data = await res.json();
        const updated = data.item;
        setSelectedItem(updated);
        setItems(prev => prev.map(i => (i.id === updated.id ? updated : i)));
        setPreviewMode('preview');
        showToast(`Documento de "${updated.name}" atualizado com sucesso!`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao salvar documento.');
      }
    } catch {
      showToast('Erro de conexão ao salvar documento.');
    } finally {
      setIsSavingDocument(false);
    }
  };

  // Copiar documento explicativo para o clipboard
  const handleCopyDocument = (text: string, itemId?: string) => {
    navigator.clipboard.writeText(text);
    if (itemId) {
      setCopiedItemId(itemId);
      setTimeout(() => setCopiedItemId(null), 2000);
    } else {
      setCopiedDocument(true);
      setTimeout(() => setCopiedDocument(false), 2000);
    }
    showToast('Documento copiado para a área de transferência.');
  };

  // Excluir método de segurança
  const handleDeleteSecurityItem = async (itemId: string, itemName: string) => {
    if (!window.confirm(`Tem certeza que deseja remover o padrão de segurança "${itemName}"?`)) {
      return;
    }

    try {
      const res = await fetch(`/api/security/${itemId}?hard=true`, { method: 'DELETE' });
      if (res.ok) {
        setItems(prev => prev.filter(i => i.id !== itemId));
        if (selectedItem?.id === itemId) {
          setSelectedItem(null);
        }
        showToast(`Padrão "${itemName}" excluído com sucesso.`);
      } else {
        const err = await res.json();
        showToast(err.error || 'Erro ao excluir padrão.');
      }
    } catch {
      showToast('Erro ao excluir padrão de segurança.');
    }
  };

  // Cadastrar Novo Padrão de Segurança
  const handleCreateSecuritySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) {
      showToast('Informe o nome da tecnologia/padrão de segurança.');
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

      const initialDoc = newDocumentContent.trim() || `# ${newName.trim()}

## 1. Visão Geral
${newDesc.trim() || 'Descreva o propósito e regras deste método de segurança.'}

## 2. Como Aplicar nos Projetos
1. Inclua as validações necessárias nos endpoints e fluxos.
2. Certifique-se de manter logs e testes de conformidade.

## 3. Checklist de Implementação
- [ ] Implementado no código-fonte
- [ ] Testes de conformidade e segurança executados
- [ ] Regras validadas em produção
`;

      const res = await fetch('/api/security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newName.trim(),
          description: newDesc.trim() || 'Diretriz técnica de segurança corporativa.',
          category: newCategory,
          severity: newSeverity,
          complianceStandards: complianceList,
          tags: tagList,
          content: initialDoc
        })
      });

      if (res.ok) {
        const data = await res.json();
        setItems(prev => [data.item, ...prev]);
        setIsCreateModalOpen(false);
        setNewName('');
        setNewDesc('');
        setNewDocumentContent('');
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

  // Renderizador seguro e de alta fidelidade de Markdown
  const renderMarkdownPreview = (text: string) => {
    const lines = text.split('\n');
    return (
      <div className="space-y-3 font-sans text-xs leading-relaxed text-zinc-300">
        {lines.map((line, idx) => {
          if (line.startsWith('### ')) {
            return (
              <h4 key={idx} className="text-sm font-bold text-foreground mt-4 mb-2 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                {line.replace('### ', '')}
              </h4>
            );
          }
          if (line.startsWith('## ')) {
            return (
              <h3 key={idx} className="text-base font-extrabold text-foreground mt-6 mb-2 pb-1.5 border-b border-zinc-800 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-primary" />
                {line.replace('## ', '')}
              </h3>
            );
          }
          if (line.startsWith('# ')) {
            return (
              <h2 key={idx} className="text-xl font-black text-primary mt-6 mb-3 pb-2 border-b border-primary/20">
                {line.replace('# ', '')}
              </h2>
            );
          }
          if (line.startsWith('- [ ] ') || line.startsWith('- [x] ')) {
            const isChecked = line.startsWith('- [x] ');
            return (
              <div key={idx} className="flex items-center gap-2 pl-2 py-0.5">
                <input type="checkbox" readOnly checked={isChecked} className="rounded accent-primary cursor-default" />
                <span className={isChecked ? 'line-through text-zinc-500 font-mono text-[11px]' : 'text-zinc-200 font-mono text-[11px]'}>
                  {line.substring(6)}
                </span>
              </div>
            );
          }
          if (line.startsWith('- ') || line.startsWith('* ')) {
            return (
              <div key={idx} className="flex items-start gap-2 pl-3">
                <span className="text-primary mt-0.5">•</span>
                <span>{line.substring(2)}</span>
              </div>
            );
          }
          if (/^\d+\.\s/.test(line)) {
            const match = line.match(/^(\d+)\.\s(.*)/);
            return (
              <div key={idx} className="flex items-start gap-2 pl-3">
                <span className="text-primary font-bold text-[11px]">{match ? match[1] + '.' : '•'}</span>
                <span>{match ? match[2] : line}</span>
              </div>
            );
          }
          if (line.startsWith('```')) {
            return (
              <div key={idx} className="font-mono text-[11px] bg-zinc-950 p-3 rounded-xl border border-zinc-800 text-zinc-300 overflow-x-auto my-2">
                {line}
              </div>
            );
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
          <div>
            <div className="flex items-center gap-3">
              <span className="p-2.5 rounded-xl bg-primary/10 border border-primary/20 text-primary shadow-inner">
                <ShieldCheck size={26} />
              </span>
              <div>
                <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
                  Biblioteca de Segurança
                </h1>
                <p className="text-xs sm:text-sm text-zinc-400 mt-1">
                  Catálogo de diretrizes, métodos e arquiteturas de proteção para consultar e aplicar nos projetos.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-xs transition-all shadow-lg shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            >
              <Plus size={16} />
              Nova Diretriz de Segurança
            </button>
          </div>
        </div>

        {/* Estatísticas Rápidas */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8 pt-6 border-t border-zinc-800/60">
          <div className="p-4 rounded-2xl bg-zinc-900/40 border border-zinc-800/60">
            <div className="text-[10px] uppercase font-mono tracking-wider text-zinc-500">Padrões Cadastrados</div>
            <div className="text-2xl font-bold text-foreground mt-1">{items.length}</div>
          </div>
          <div className="p-4 rounded-2xl bg-zinc-900/40 border border-zinc-800/60">
            <div className="text-[10px] uppercase font-mono tracking-wider text-zinc-500">Crítico & Alto Impacto</div>
            <div className="text-2xl font-bold text-rose-400 mt-1">
              {items.filter(i => i.severity === 'critico' || i.severity === 'alto').length}
            </div>
          </div>
          <div className="p-4 rounded-2xl bg-zinc-900/40 border border-zinc-800/60">
            <div className="text-[10px] uppercase font-mono tracking-wider text-zinc-500">Categorias Ativas</div>
            <div className="text-2xl font-bold text-primary mt-1">
              {new Set(items.map(i => i.category)).size}
            </div>
          </div>
          <div className="p-4 rounded-2xl bg-zinc-900/40 border border-zinc-800/60">
            <div className="text-[10px] uppercase font-mono tracking-wider text-zinc-500">Conformidade</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">OWASP & LGPD</div>
          </div>
        </div>
      </div>

      {/* Barra de Filtros e Busca */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          {/* Campo de Busca */}
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-500" size={16} />
            <input
              type="text"
              placeholder="Buscar por método de segurança, tag ou norma (ex: LGPD, OWASP, ABAC)..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-zinc-900/80 border border-zinc-800 text-xs text-foreground placeholder:text-zinc-500 focus:outline-none focus:border-primary/50 transition-colors shadow-inner"
            />
          </div>

          {/* Filtro de Severidade e Modo de Visualização */}
          <div className="flex items-center gap-2">
            <select
              value={selectedSeverity}
              onChange={e => setSelectedSeverity(e.target.value)}
              aria-label="Filtrar por severidade de segurança"
              className="px-3 py-2.5 rounded-xl bg-zinc-900/80 border border-zinc-800 text-xs text-zinc-300 focus:outline-none focus:border-primary/50 cursor-pointer"
            >
              {SEVERITIES.map(s => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>

            <div className="flex items-center bg-zinc-900/80 border border-zinc-800 rounded-xl p-0.5">
              <button
                onClick={() => setViewMode('cards')}
                className={`p-2 rounded-lg transition-colors cursor-pointer ${
                  viewMode === 'cards' ? 'bg-zinc-800 text-primary' : 'text-zinc-500 hover:text-zinc-300'
                }`}
                title="Visualização em Cards"
              >
                <LayoutGrid size={15} />
              </button>
              <button
                onClick={() => setViewMode('table')}
                className={`p-2 rounded-lg transition-colors cursor-pointer ${
                  viewMode === 'table' ? 'bg-zinc-800 text-primary' : 'text-zinc-500 hover:text-zinc-300'
                }`}
                title="Visualização em Tabela"
              >
                <TableIcon size={15} />
              </button>
            </div>
          </div>
        </div>

        {/* Abas de Categorias */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
          {CATEGORIES.map(cat => {
            const isSelected = selectedCategory === cat.id;
            const count = cat.id === 'todas'
              ? items.length
              : items.filter(i => i.category === cat.id).length;

            return (
              <button
                key={cat.id}
                onClick={() => setSelectedCategory(cat.id)}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-medium whitespace-nowrap transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-zinc-800 text-primary border border-primary/30 shadow-sm'
                    : 'bg-zinc-900/50 hover:bg-zinc-800/50 text-zinc-400 hover:text-zinc-200 border border-zinc-800/60'
                }`}
              >
                <span>{cat.label}</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                  isSelected ? 'bg-primary/20 text-primary' : 'bg-zinc-800 text-zinc-500'
                }`}>
                  {count}
                </span>
              </button>
            );
          })}
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
          <h3 className="text-base font-semibold text-foreground">Nenhuma diretriz de segurança encontrada</h3>
          <p className="text-xs text-zinc-500 mt-1 max-w-md mx-auto">
            Tente alterar o termo de pesquisa, o filtro de severidade ou cadastre uma nova diretriz.
          </p>
        </div>
      ) : viewMode === 'cards' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredItems.map(item => {
            const docContent = item.content || (item.files?.[0]?.content) || item.description || '';
            const isCopied = copiedItemId === item.id;

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
                  <h3
                    onClick={() => handleOpenItemDetails(item, 'preview')}
                    className="text-lg font-bold text-foreground group-hover:text-primary transition-colors cursor-pointer"
                  >
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

                  {/* Tags Dinâmicas */}
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

                {/* Footer do Card com Ações Diretas */}
                <div className="mt-6 pt-4 border-t border-zinc-800/60 flex items-center justify-between gap-3">
                  <button
                    onClick={() => handleCopyDocument(docContent, item.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800/60 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 text-xs font-medium cursor-pointer transition-colors border border-zinc-700/40"
                    title="Copiar diretriz para área de transferência"
                  >
                    {isCopied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                    <span>{isCopied ? 'Copiado!' : 'Copiar'}</span>
                  </button>

                  <button
                    onClick={() => handleOpenItemDetails(item, 'preview')}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 text-xs font-semibold cursor-pointer transition-all hover:scale-[1.02] active:scale-[0.98]"
                  >
                    <FileText size={13} />
                    Consultar Diretriz
                  </button>
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
                <th className="py-3 px-4">Tags</th>
                <th className="py-3 px-4 text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {filteredItems.map(item => {
                const docContent = item.content || (item.files?.[0]?.content) || item.description || '';
                const isCopied = copiedItemId === item.id;

                return (
                  <tr key={item.id} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-foreground cursor-pointer hover:text-primary transition-colors" onClick={() => handleOpenItemDetails(item, 'preview')}>
                        {item.name}
                      </div>
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
                    <td className="py-3 px-4 text-zinc-400 font-mono text-[10px]">
                      {item.tags.map(t => `#${t}`).join(' ')}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleCopyDocument(docContent, item.id)}
                          className="p-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 cursor-pointer transition-colors"
                          title="Copiar documento"
                        >
                          {isCopied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                        </button>
                        <button
                          onClick={() => handleOpenItemDetails(item, 'preview')}
                          className="px-3 py-1.5 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 text-xs font-semibold cursor-pointer transition-colors"
                        >
                          Consultar
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Modal de Detalhes e Documento Explicativo */}
      <AnimatePresence>
        {selectedItem && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-4xl max-h-[92vh] flex flex-col rounded-3xl bg-zinc-950 border border-zinc-800 shadow-2xl overflow-hidden"
            >
              {/* Header do Modal */}
              <div className="px-6 py-5 border-b border-zinc-800 flex items-start justify-between gap-4 bg-zinc-900/60">
                <div className="flex items-start gap-3.5">
                  <div className="w-11 h-11 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary flex-shrink-0 mt-0.5 shadow-inner">
                    <ShieldCheck size={22} />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-lg sm:text-xl font-bold text-foreground">{selectedItem.name}</h2>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-300 border border-zinc-700/60">
                        {selectedItem.category}
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full capitalize font-semibold ${
                        selectedItem.severity === 'critico' ? 'bg-rose-950/80 text-rose-400 border border-rose-800/60' :
                        selectedItem.severity === 'alto' ? 'bg-amber-950/80 text-amber-400 border border-amber-800/60' :
                        selectedItem.severity === 'medio' ? 'bg-blue-950/80 text-blue-400 border border-blue-800/60' :
                        'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                      }`}>
                        {selectedItem.severity}
                      </span>
                    </div>
                    <p className="text-xs text-zinc-400 mt-1">{selectedItem.description}</p>

                    {/* Normas e Tags */}
                    <div className="flex flex-wrap items-center gap-2 mt-2">
                      {selectedItem.complianceStandards && selectedItem.complianceStandards.length > 0 && (
                        <div className="flex items-center gap-1">
                          {selectedItem.complianceStandards.map(comp => (
                            <span key={comp} className="text-[10px] px-2 py-0.2 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/40 font-mono">
                              {comp}
                            </span>
                          ))}
                        </div>
                      )}
                      <div className="flex items-center gap-1">
                        {selectedItem.tags.map(t => (
                          <span key={t} className="text-[10px] font-mono text-zinc-500">#{t}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => setSelectedItem(null)}
                  className="p-2 rounded-xl text-zinc-400 hover:text-foreground hover:bg-white/5 cursor-pointer transition-colors"
                  title="Fechar modal"
                >
                  <X size={18} />
                </button>
              </div>

              {/* Barra de Ferramentas do Documento Explicativo */}
              <div className="px-6 py-3 border-b border-zinc-800/60 bg-zinc-900/40 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
                    <FileText size={14} className="text-primary" />
                    Documento Explicativo & Diretriz de Aplicação
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <div className="flex items-center bg-zinc-900 rounded-lg p-0.5 border border-zinc-800 text-xs">
                    <button
                      onClick={() => setPreviewMode('preview')}
                      className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-colors cursor-pointer ${
                        previewMode === 'preview' ? 'bg-zinc-800 text-primary font-semibold' : 'text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      <Eye size={13} />
                      Visualizar
                    </button>
                    <button
                      onClick={() => setPreviewMode('edit')}
                      className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-colors cursor-pointer ${
                        previewMode === 'edit' ? 'bg-zinc-800 text-primary font-semibold' : 'text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      <Code2 size={13} />
                      Editar
                    </button>
                  </div>

                  <button
                    onClick={() => handleCopyDocument(documentEditorContent)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-zinc-100 text-xs font-medium cursor-pointer transition-colors"
                    title="Copiar documento"
                  >
                    {copiedDocument ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                    <span>{copiedDocument ? 'Copiado!' : 'Copiar'}</span>
                  </button>

                  {previewMode === 'edit' && (
                    <button
                      onClick={handleSaveDocumentContent}
                      disabled={isSavingDocument}
                      className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-semibold cursor-pointer transition-all shadow-md shadow-primary/20"
                    >
                      <Save size={13} />
                      {isSavingDocument ? 'Salvando...' : 'Salvar Alterações'}
                    </button>
                  )}
                </div>
              </div>

              {/* Conteúdo do Documento */}
              <div className="flex-1 overflow-y-auto p-6 sm:p-8 bg-zinc-950">
                {previewMode === 'preview' ? (
                  <div className="max-w-3xl mx-auto">
                    {renderMarkdownPreview(documentEditorContent)}
                  </div>
                ) : (
                  <div className="h-full flex flex-col">
                    <textarea
                      value={documentEditorContent}
                      onChange={e => setDocumentEditorContent(e.target.value)}
                      placeholder="Escreva a documentação explicativa e as diretrizes práticas de aplicação nos projetos..."
                      rows={18}
                      className="w-full h-full min-h-[420px] p-4 rounded-2xl bg-zinc-900/90 border border-zinc-800 text-xs text-foreground font-mono leading-relaxed focus:outline-none focus:border-primary/50 resize-y"
                    />
                  </div>
                )}
              </div>

              {/* Rodapé do Modal */}
              <div className="px-6 py-3.5 border-t border-zinc-800 bg-zinc-900/60 flex items-center justify-between text-xs text-zinc-500">
                <div className="flex items-center gap-2">
                  <span>Atualizado em: {new Date(selectedItem.updatedAt).toLocaleDateString('pt-BR')}</span>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    onClick={() => handleDeleteSecurityItem(selectedItem.id, selectedItem.name)}
                    className="flex items-center gap-1 text-xs text-zinc-500 hover:text-rose-400 cursor-pointer transition-colors"
                  >
                    <Trash2 size={13} />
                    Excluir Diretriz
                  </button>
                  <button
                    onClick={() => setSelectedItem(null)}
                    className="px-4 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium cursor-pointer transition-colors"
                  >
                    Fechar
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Modal de Cadastrar Nova Diretriz de Segurança (Sem Arquivos) */}
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
                    <h3 className="text-lg font-bold text-foreground">Nova Diretriz de Segurança</h3>
                    <p className="text-xs text-zinc-400">Cadastre um documento explicativo para consulta e aplicação nos projetos.</p>
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
                    Nome da Diretriz / Método de Segurança
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="Ex: Proteção contra Injeção de SQL e Sanitização Zod"
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
                      aria-label="Categoria técnica de segurança"
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
                    <label className="block text-xs font-medium text-zinc-400 mb-1">Nível de Severidade / Impacto</label>
                    <select
                      value={newSeverity}
                      onChange={e => setNewSeverity(e.target.value as any)}
                      aria-label="Nível de severidade ou impacto de segurança"
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
                  <label className="block text-xs font-medium text-zinc-400 mb-1">Resumo Conciso</label>
                  <textarea
                    rows={2}
                    required
                    placeholder="Explicação rápida do objetivo desta diretriz..."
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
                      placeholder="LGPD, OWASP Top 10, NIST SP 800-53"
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
                      placeholder="sql, sanitizacao, prisma, zod"
                      value={newTags}
                      onChange={e => setNewTags(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-foreground focus:outline-none focus:border-primary/50"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-400 mb-1">
                    Documento Explicativo (Como funciona e como aplicar nos projetos)
                  </label>
                  <textarea
                    rows={8}
                    placeholder={`# Nome da Diretriz\n\n## 1. Visão Geral\nExplicação de como funciona o método...\n\n## 2. Como Aplicar nos Projetos\nInstruções práticas de implementação...`}
                    value={newDocumentContent}
                    onChange={e => setNewDocumentContent(e.target.value)}
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
                    {isSubmitting ? 'Cadastrando...' : 'Cadastrar Diretriz'}
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
