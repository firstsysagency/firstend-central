import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  Plus,
  Copy,
  Check,
  X,
  Save,
  LayoutGrid,
  Table as TableIcon,
  Eye,
  AlertTriangle,
  Info,
  Layers,
  Clock,
  UploadCloud,
  Lock,
  Network,
  Cpu,
  Database,
  Key,
  Radio,
  FileCheck2,
  RefreshCw
} from 'lucide-react';
import type {
  SecurityControl,
  SecurityControlCategory,
  SecurityControlSeverity,
  SecurityControlStatus,
  SecurityControlEvidence,
  SecurityControlException,
  SecurityAuditEvent,
  SecurityPostureSummary
} from '../types/security';

const CONTROL_CATEGORIES: { id: string; label: string; icon: any }[] = [
  { id: 'todas', label: 'Todos os 100 Controles', icon: ShieldCheck },
  { id: 'rede', label: 'Rede', icon: Network },
  { id: 'trafego', label: 'Tráfego & TLS', icon: Radio },
  { id: 'api', label: 'API & CORS', icon: Layers },
  { id: 'autenticacao', label: 'Autenticação & MFA', icon: Key },
  { id: 'dados', label: 'Dados & LGPD', icon: Database },
  { id: 'infraestrutura', label: 'Infraestrutura & SO', icon: Cpu },
  { id: 'aplicacao', label: 'Aplicação & AppSec', icon: Lock },
  { id: 'monitoramento', label: 'Monitoramento & Logs', icon: Clock },
  { id: 'incidentes', label: 'Incidentes & DR', icon: ShieldAlert },
  { id: 'governanca', label: 'Governança & RBAC', icon: FileCheck2 }
];

const SEVERITY_CONFIG: Record<SecurityControlSeverity, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: 'Crítico', color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/30' },
  high: { label: 'Alto', color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
  medium: { label: 'Médio', color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30' },
  low: { label: 'Baixo', color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' }
};

const STATUS_CONFIG: Record<SecurityControlStatus, { label: string; color: string; bg: string; border: string }> = {
  verified: { label: 'Verificado', color: 'text-emerald-300', bg: 'bg-emerald-500/15', border: 'border-emerald-500/30' },
  implemented: { label: 'Implementado', color: 'text-teal-300', bg: 'bg-teal-500/15', border: 'border-teal-500/30' },
  in_progress: { label: 'Em Progresso', color: 'text-amber-300', bg: 'bg-amber-500/15', border: 'border-amber-500/30' },
  planned: { label: 'Planejado', color: 'text-zinc-400', bg: 'bg-zinc-800/60', border: 'border-zinc-700/50' },
  exception: { label: 'Exceção / Risco', color: 'text-purple-300', bg: 'bg-purple-500/15', border: 'border-purple-500/30' },
  not_applicable: { label: 'Não Aplicável', color: 'text-zinc-500', bg: 'bg-zinc-900', border: 'border-zinc-800' }
};

export default function Security() {
  const [controls, setControls] = useState<SecurityControl[]>([]);
  const [posture, setPosture] = useState<SecurityPostureSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('todas');
  const [selectedStatus, setSelectedStatus] = useState('todas');
  const [selectedSeverity, setSelectedSeverity] = useState('todas');
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Modal de Detalhes do Controle
  const [selectedControl, setSelectedControl] = useState<SecurityControl | null>(null);
  const [activeModalTab, setActiveModalTab] = useState<'overview' | 'implementation' | 'evidence' | 'exceptions' | 'audit'>('overview');
  const [isEditing, setIsEditing] = useState(false);
  const [editForm, setEditForm] = useState<Partial<SecurityControl>>({});
  const [isSaving, setIsSaving] = useState(false);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  // Evidências do Controle
  const [controlEvidences, setControlEvidences] = useState<SecurityControlEvidence[]>([]);
  const [isCreatingEvidence, setIsCreatingEvidence] = useState(false);
  const [newEvidenceTitle, setNewEvidenceTitle] = useState('');
  const [newEvidenceDesc, setNewEvidenceDesc] = useState('');
  const [newEvidenceType, setNewEvidenceType] = useState<any>('report');
  const [newEvidenceData, setNewEvidenceData] = useState('');

  // Exceções do Controle
  const [controlExceptions, setControlExceptions] = useState<SecurityControlException[]>([]);
  const [isCreatingException, setIsCreatingException] = useState(false);
  const [newExceptionReason, setNewExceptionReason] = useState('');
  const [newExceptionApprover, setNewExceptionApprover] = useState('SecOps Lead');
  const [newExceptionDays, setNewExceptionDays] = useState('30');
  const [resolvingExceptionId, setResolvingExceptionId] = useState<string | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState('');

  // Auditoria do Controle
  const [controlAuditEvents, setControlAuditEvents] = useState<SecurityAuditEvent[]>([]);

  // Modal de Novo Controle
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [createCode, setCreateCode] = useState('');
  const [createName, setCreateName] = useState('');
  const [createCategory, setCreateCategory] = useState<SecurityControlCategory>('rede');
  const [createSeverity, setCreateSeverity] = useState<SecurityControlSeverity>('high');
  const [createStatus, setCreateStatus] = useState<SecurityControlStatus>('planned');
  const [createOwner, setCreateOwner] = useState('SecOps Team');
  const [createDesc, setCreateDesc] = useState('');
  const [createRationale, setCreateRationale] = useState('');
  const [createImplementation, setCreateImplementation] = useState('');
  const [createValidation, setCreateValidation] = useState('');
  const [isCreatingControl, setIsCreatingControl] = useState(false);

  // Modal de Importação em Massa (Preview & Commit)
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importJsonText, setImportJsonText] = useState('');
  const [importPreviewResult, setImportPreviewResult] = useState<any | null>(null);
  const [isProcessingImport, setIsProcessingImport] = useState(false);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Carregar lista de controles e postura
  const loadData = async () => {
    try {
      setIsLoading(true);
      const [controlsRes, postureRes] = await Promise.all([
        fetch('/api/security/controls?limit=150'),
        fetch('/api/security/posture')
      ]);

      if (controlsRes.ok) {
        const cData = await controlsRes.json();
        setControls(cData.controls || []);
      }
      if (postureRes.ok) {
        const pData = await postureRes.json();
        setPosture(pData.posture || null);
      }
    } catch (err) {
      console.error('Erro ao carregar dados de segurança:', err);
      showToast('Falha ao comunicar com o servidor de segurança.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Abrir modal de detalhes
  const handleOpenControl = async (ctrl: SecurityControl) => {
    setSelectedControl(ctrl);
    setEditForm(ctrl);
    setIsEditing(false);
    setActiveModalTab('overview');

    // Carregar evidências, exceções e auditoria em paralelo
    try {
      const [evRes, exRes, audRes] = await Promise.all([
        fetch(`/api/security/controls/${ctrl.id}/evidence`),
        fetch(`/api/security/exceptions?control_code=${ctrl.control_code}`),
        fetch(`/api/security/audit-events?control_code=${ctrl.control_code}`)
      ]);

      if (evRes.ok) {
        const evData = await evRes.json();
        setControlEvidences(evData.evidences || []);
      }
      if (exRes.ok) {
        const exData = await exRes.json();
        setControlExceptions(exData.exceptions || []);
      }
      if (audRes.ok) {
        const audData = await audRes.json();
        setControlAuditEvents(audData.events || []);
      }
    } catch (e) {
      console.warn('Erro ao carregar dados auxiliares do controle:', e);
    }
  };

  // Salvar edições do controle com concorrência otimista
  const handleSaveControl = async () => {
    if (!selectedControl) return;

    try {
      setIsSaving(true);
      const res = await fetch(`/api/security/controls/${selectedControl.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          expected_revision: selectedControl.revision,
          name: editForm.name,
          category: editForm.category,
          severity: editForm.severity,
          status: editForm.status,
          owner: editForm.owner,
          description: editForm.description,
          rationale: editForm.rationale,
          implementation: editForm.implementation,
          validation_method: editForm.validation_method,
          evidence: editForm.evidence
        })
      });

      const data = await res.json();
      if (!res.ok) {
        if (res.status === 409) {
          showToast(`Conflito de concorrência: o controle foi modificado para a rev v${data.currentRevision}. Recarregue.`);
        } else {
          showToast(data.error || 'Erro ao atualizar controle.');
        }
        return;
      }

      showToast(`Controle ${data.control.control_code} atualizado com sucesso (rev v${data.control.revision})!`);
      setSelectedControl(data.control);
      setEditForm(data.control);
      setIsEditing(false);
      loadData();
    } catch (err: any) {
      showToast(err.message || 'Erro de rede ao salvar controle.');
    } finally {
      setIsSaving(false);
    }
  };

  // Anexar nova evidência
  const handleCreateEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedControl || !newEvidenceTitle.trim() || !newEvidenceDesc.trim()) return;

    try {
      const res = await fetch(`/api/security/controls/${selectedControl.id}/evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newEvidenceTitle,
          description: newEvidenceDesc,
          evidence_type: newEvidenceType,
          evidence_data: newEvidenceData
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        showToast(errData.error || 'Erro ao registrar evidência.');
        return;
      }

      const data = await res.json();
      setControlEvidences(prev => [data.evidence, ...prev]);
      setIsCreatingEvidence(false);
      setNewEvidenceTitle('');
      setNewEvidenceDesc('');
      setNewEvidenceData('');
      showToast('Evidência anexada com hash SHA-256 verificado!');
      loadData();
    } catch {
      showToast('Erro de rede ao registrar evidência.');
    }
  };

  // Registrar nova exceção
  const handleCreateException = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedControl || !newExceptionReason.trim()) return;

    try {
      const expiresAt = new Date(Date.now() + Number(newExceptionDays) * 86400000).toISOString();
      const res = await fetch(`/api/security/controls/${selectedControl.id}/exceptions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: newExceptionReason,
          approved_by: newExceptionApprover,
          risk_accepted: true,
          expires_at: expiresAt
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        showToast(errData.error || 'Erro ao registrar exceção.');
        return;
      }

      const data = await res.json();
      setControlExceptions(prev => [data.exception, ...prev]);
      setIsCreatingException(false);
      setNewExceptionReason('');
      showToast('Exceção de segurança registrada e status atualizado!');
      loadData();
      if (selectedControl) {
        setSelectedControl({ ...selectedControl, status: 'exception', revision: selectedControl.revision + 1 });
      }
    } catch {
      showToast('Erro de rede ao registrar exceção.');
    }
  };

  // Resolver exceção
  const handleResolveException = async (exceptionId: string) => {
    if (!resolutionNotes.trim()) {
      showToast('Informe as notas de resolução.');
      return;
    }

    try {
      const res = await fetch(`/api/security/exceptions/${exceptionId}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resolution_notes: resolutionNotes
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        showToast(errData.error || 'Erro ao resolver exceção.');
        return;
      }

      const data = await res.json();
      setControlExceptions(prev => prev.map(ex => ex.id === exceptionId ? data.exception : ex));
      setResolvingExceptionId(null);
      setResolutionNotes('');
      showToast('Exceção resolvida e controle retornado ao ciclo de conformidade!');
      loadData();
    } catch {
      showToast('Erro de rede ao resolver exceção.');
    }
  };

  // Criar novo controle
  const handleCreateNewControl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createCode.trim() || !createName.trim() || !createDesc.trim()) return;

    try {
      setIsCreatingControl(true);
      const res = await fetch('/api/security/controls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          control_code: createCode.toUpperCase().trim(),
          name: createName.trim(),
          category: createCategory,
          severity: createSeverity,
          status: createStatus,
          owner: createOwner.trim(),
          description: createDesc.trim(),
          rationale: createRationale.trim(),
          implementation: createImplementation.trim(),
          validation_method: createValidation.trim()
        })
      });

      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Erro ao criar controle.');
        return;
      }

      showToast(`Controle ${data.control.control_code} cadastrado com sucesso!`);
      setIsCreateModalOpen(false);
      setCreateCode('');
      setCreateName('');
      setCreateDesc('');
      setCreateRationale('');
      setCreateImplementation('');
      setCreateValidation('');
      loadData();
    } catch (err: any) {
      showToast(err.message || 'Erro ao cadastrar controle.');
    } finally {
      setIsCreatingControl(false);
    }
  };

  // Prévia de Importação
  const handleImportPreview = async () => {
    try {
      const parsed = JSON.parse(importJsonText);
      const items = Array.isArray(parsed) ? parsed : [parsed];

      setIsProcessingImport(true);
      const res = await fetch('/api/security/controls/import/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ controls: items })
      });

      const data = await res.json();
      setImportPreviewResult(data.preview || data);
      showToast(data.preview?.ok ? 'Prévia gerada com sucesso!' : 'Erros detectados no lote.');
    } catch {
      showToast('JSON inválido. Certifique-se de colar um array JSON válido.');
    } finally {
      setIsProcessingImport(false);
    }
  };

  // Confirmação de Importação
  const handleImportCommit = async () => {
    try {
      const parsed = JSON.parse(importJsonText);
      const items = Array.isArray(parsed) ? parsed : [parsed];

      setIsProcessingImport(true);
      const res = await fetch('/api/security/controls/import/commit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          controls: items,
          idempotency_key: `import_ui_${Date.now()}`
        })
      });

      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Erro ao confirmar importação.');
        return;
      }

      showToast(data.message || 'Importação gravada com sucesso!');
      setIsImportModalOpen(false);
      setImportJsonText('');
      setImportPreviewResult(null);
      loadData();
    } catch {
      showToast('Falha ao processar gravação da importação.');
    } finally {
      setIsProcessingImport(false);
    }
  };

  // Copiar código ou diretriz
  const copyToClipboard = (text: string, code: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(code);
    showToast(`Código ${code} copiado para a área de transferência!`);
    setTimeout(() => setCopiedCode(null), 2500);
  };

  // Filtros combinados
  const filteredControls = useMemo(() => {
    return controls.filter(c => {
      const matchesSearch =
        searchTerm === '' ||
        c.control_code.toLowerCase().includes(searchTerm.toLowerCase()) ||
        c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        c.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        c.rationale.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesCategory = selectedCategory === 'todas' || c.category === selectedCategory;
      const matchesStatus = selectedStatus === 'todas' || c.status === selectedStatus;
      const matchesSeverity = selectedSeverity === 'todas' || c.severity === selectedSeverity;

      return matchesSearch && matchesCategory && matchesStatus && matchesSeverity;
    });
  }, [controls, searchTerm, selectedCategory, selectedStatus, selectedSeverity]);

  return (
    <div className="min-h-screen bg-[#090D16] text-zinc-100 font-sans pb-24">
      {/* Toast Notification */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed top-6 right-6 z-50 bg-zinc-900 border border-emerald-500/40 text-emerald-300 px-5 py-3 rounded-xl shadow-2xl flex items-center gap-3 backdrop-blur-md"
          >
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span className="text-sm font-medium">{toastMessage}</span>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8">
        {/* Cabeçalho da Seção */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-8 border-b border-zinc-800/80">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                <ShieldCheck className="w-6 h-6" />
              </span>
              <span className="text-xs uppercase tracking-widest font-semibold text-emerald-400">
                Segurança Corporativa & Postura MCP
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              100 Controles de Segurança Corporativa
            </h1>
            <p className="mt-2 text-sm text-zinc-400 max-w-3xl leading-relaxed">
              Catálogo formal de controles arquiteturais independentes expostos via protocolo MCP.
              Governança contínua com concorrência otimista, hashes SHA-256 de evidências e trilha imutável.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={() => setIsImportModalOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-zinc-900 border border-zinc-700/80 hover:border-zinc-500 text-sm font-medium text-zinc-200 hover:text-white transition-all shadow-sm"
            >
              <UploadCloud className="w-4 h-4 text-zinc-400" />
              Importar / Exportar Lote
            </button>
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-sm font-semibold text-white transition-all shadow-lg shadow-emerald-950/40"
            >
              <Plus className="w-4 h-4" />
              Novo Controle
            </button>
          </div>
        </div>

        {/* KPIs / Cards de Postura de Segurança */}
        {posture && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mt-8">
            <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-4 flex flex-col justify-between backdrop-blur-sm">
              <div className="flex items-center justify-between text-zinc-400 text-xs font-medium">
                <span>Total de Controles</span>
                <Layers className="w-4 h-4 text-zinc-500" />
              </div>
              <div className="mt-2">
                <span className="text-3xl font-black text-white">{posture.total_controls}</span>
                <span className="text-xs text-zinc-500 ml-2">ativos</span>
              </div>
              <div className="mt-2 text-[11px] text-zinc-500">10 categorias balanceadas</div>
            </div>

            <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-2xl p-4 flex flex-col justify-between backdrop-blur-sm">
              <div className="flex items-center justify-between text-emerald-400/80 text-xs font-medium">
                <span>Implementados / Verificados</span>
                <Check className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2">
                <span className="text-3xl font-black text-emerald-400">
                  {posture.by_status.implemented + posture.by_status.verified}
                </span>
                <span className="text-xs text-emerald-500/80 ml-2">controles</span>
              </div>
              <div className="mt-2 text-[11px] text-emerald-400/60">Efetividade comprovada</div>
            </div>

            <div className="bg-amber-950/20 border border-amber-500/20 rounded-2xl p-4 flex flex-col justify-between backdrop-blur-sm">
              <div className="flex items-center justify-between text-amber-400/80 text-xs font-medium">
                <span>Em Progresso / Planejados</span>
                <Clock className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-2">
                <span className="text-3xl font-black text-amber-400">
                  {posture.by_status.in_progress + posture.by_status.planned}
                </span>
                <span className="text-xs text-amber-500/80 ml-2">em pipeline</span>
              </div>
              <div className="mt-2 text-[11px] text-amber-400/60">Acompanhamento contínuo</div>
            </div>

            <div className="bg-purple-950/20 border border-purple-500/20 rounded-2xl p-4 flex flex-col justify-between backdrop-blur-sm">
              <div className="flex items-center justify-between text-purple-400/80 text-xs font-medium">
                <span>Exceções Ativas</span>
                <AlertTriangle className="w-4 h-4 text-purple-400" />
              </div>
              <div className="mt-2">
                <span className="text-3xl font-black text-purple-400">{posture.active_exceptions_count}</span>
                <span className="text-xs text-purple-500/80 ml-2">riscos aceitos</span>
              </div>
              <div className="mt-2 text-[11px] text-purple-400/60">Com prazo e aprovador</div>
            </div>

            <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-4 flex flex-col justify-between backdrop-blur-sm">
              <div className="flex items-center justify-between text-zinc-400 text-xs font-medium">
                <span>Taxa de Conformidade</span>
                <ShieldCheck className="w-4 h-4 text-teal-400" />
              </div>
              <div className="mt-2">
                <span className="text-3xl font-black text-teal-400">{posture.compliance_rate_percent}%</span>
              </div>
              <div className="mt-2 text-[11px] text-zinc-500">
                {posture.overdue_reviews_count > 0 ? (
                  <span className="text-rose-400 font-medium">{posture.overdue_reviews_count} revisões vencidas</span>
                ) : (
                  'Todas as revisões em dia'
                )}
              </div>
            </div>
          </div>
        )}

        {/* Barra de Filtros e Categorias */}
        <div className="mt-8 space-y-4">
          {/* Seletor de Categoria em Pílulas */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
            {CONTROL_CATEGORIES.map(cat => {
              const Icon = cat.icon;
              const isSelected = selectedCategory === cat.id;
              return (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
                    isSelected
                      ? 'bg-emerald-500 text-zinc-950 font-bold shadow-lg shadow-emerald-500/20'
                      : 'bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 border border-zinc-800/80'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {cat.label}
                </button>
              );
            })}
          </div>

          {/* Busca e Filtros de Status / Severidade / Visualização */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-zinc-900/40 p-3 rounded-2xl border border-zinc-800/60">
            <div className="relative w-full sm:w-96">
              <Search className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Buscar por código (SEC-001) ou palavra-chave..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500/60 transition-all"
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="flex items-center gap-2.5 w-full sm:w-auto justify-end flex-wrap">
              <select
                value={selectedStatus}
                onChange={e => setSelectedStatus(e.target.value)}
                className="px-3 py-2 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 focus:outline-none focus:border-emerald-500/50"
              >
                <option value="todas">Todos os Status</option>
                <option value="verified">Verificado</option>
                <option value="implemented">Implementado</option>
                <option value="in_progress">Em Progresso</option>
                <option value="planned">Planejado</option>
                <option value="exception">Exceção</option>
              </select>

              <select
                value={selectedSeverity}
                onChange={e => setSelectedSeverity(e.target.value)}
                className="px-3 py-2 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 focus:outline-none focus:border-emerald-500/50"
              >
                <option value="todas">Todas as Severidades</option>
                <option value="critical">Crítica</option>
                <option value="high">Alta</option>
                <option value="medium">Média</option>
                <option value="low">Baixa</option>
              </select>

              <div className="flex items-center bg-zinc-950 border border-zinc-800 rounded-xl p-1">
                <button
                  onClick={() => setViewMode('cards')}
                  className={`p-1.5 rounded-lg text-xs transition-all ${
                    viewMode === 'cards' ? 'bg-zinc-800 text-white' : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                  title="Visualização em Cartões"
                >
                  <LayoutGrid className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setViewMode('table')}
                  className={`p-1.5 rounded-lg text-xs transition-all ${
                    viewMode === 'table' ? 'bg-zinc-800 text-white' : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                  title="Visualização em Tabela"
                >
                  <TableIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Listagem de Controles */}
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-24 text-zinc-500">
            <RefreshCw className="w-8 h-8 animate-spin text-emerald-500 mb-3" />
            <p className="text-sm">Carregando os 100 controles de segurança...</p>
          </div>
        ) : filteredControls.length === 0 ? (
          <div className="text-center py-20 bg-zinc-900/20 rounded-3xl border border-zinc-800/60 mt-8">
            <ShieldAlert className="w-12 h-12 text-zinc-600 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-zinc-300">Nenhum controle encontrado</h3>
            <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
              Nenhum controle corresponde aos filtros selecionados. Tente ajustar a busca ou categoria.
            </p>
          </div>
        ) : viewMode === 'cards' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 mt-6">
            {filteredControls.map(ctrl => {
              const sev = SEVERITY_CONFIG[ctrl.severity] || SEVERITY_CONFIG.medium;
              const st = STATUS_CONFIG[ctrl.status] || STATUS_CONFIG.planned;

              return (
                <div
                  key={ctrl.id}
                  className="bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700/80 rounded-2xl p-5 flex flex-col justify-between transition-all hover:shadow-xl group backdrop-blur-sm"
                >
                  <div>
                    {/* Topo do Card */}
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <span className="font-mono text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-lg">
                        {ctrl.control_code}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${sev.bg} ${sev.color} ${sev.border}`}>
                          {sev.label}
                        </span>
                        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${st.bg} ${st.color} ${st.border}`}>
                          {st.label}
                        </span>
                      </div>
                    </div>

                    {/* Título e Categoria */}
                    <h3 className="text-base font-bold text-white group-hover:text-emerald-300 transition-colors line-clamp-2">
                      {ctrl.name}
                    </h3>
                    <div className="text-[11px] text-zinc-500 uppercase tracking-wider font-semibold mt-1">
                      Categoria: {ctrl.category}
                    </div>

                    {/* Descrição resumida */}
                    <p className="text-xs text-zinc-400 mt-2.5 line-clamp-3 leading-relaxed">
                      {ctrl.description}
                    </p>
                  </div>

                  {/* Rodapé do Card */}
                  <div className="mt-5 pt-3.5 border-t border-zinc-800/80 flex items-center justify-between text-xs">
                    <div className="text-[11px] text-zinc-500">
                      <span>Rev v{ctrl.revision}</span>
                      <span className="mx-1.5">•</span>
                      <span>{ctrl.owner}</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => copyToClipboard(ctrl.control_code, ctrl.control_code)}
                        className="p-1.5 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors"
                        title="Copiar Código"
                      >
                        {copiedCode === ctrl.control_code ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                      <button
                        onClick={() => handleOpenControl(ctrl)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-xs font-semibold text-zinc-200 hover:text-white transition-all"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Detalhes
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          /* Visualização em Tabela */
          <div className="mt-6 bg-zinc-900/60 border border-zinc-800 rounded-2xl overflow-hidden backdrop-blur-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-zinc-950/80 border-b border-zinc-800 text-zinc-400 font-semibold uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="px-4 py-3.5">Código</th>
                    <th className="px-4 py-3.5">Nome do Controle</th>
                    <th className="px-4 py-3.5">Categoria</th>
                    <th className="px-4 py-3.5">Severidade</th>
                    <th className="px-4 py-3.5">Status</th>
                    <th className="px-4 py-3.5">Responsável</th>
                    <th className="px-4 py-3.5">Revisão</th>
                    <th className="px-4 py-3.5 text-right">Ação</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50 text-zinc-300">
                  {filteredControls.map(ctrl => {
                    const sev = SEVERITY_CONFIG[ctrl.severity] || SEVERITY_CONFIG.medium;
                    const st = STATUS_CONFIG[ctrl.status] || STATUS_CONFIG.planned;
                    return (
                      <tr key={ctrl.id} className="hover:bg-zinc-800/40 transition-colors">
                        <td className="px-4 py-3 font-mono font-bold text-emerald-400">{ctrl.control_code}</td>
                        <td className="px-4 py-3 font-medium text-white max-w-xs truncate">{ctrl.name}</td>
                        <td className="px-4 py-3 text-zinc-400 uppercase text-[10px] font-semibold">{ctrl.category}</td>
                        <td className="px-4 py-3">
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${sev.bg} ${sev.color} ${sev.border}`}>
                            {sev.label}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${st.bg} ${st.color} ${st.border}`}>
                            {st.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-zinc-400">{ctrl.owner}</td>
                        <td className="px-4 py-3 text-zinc-500 font-mono">v{ctrl.revision}</td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => handleOpenControl(ctrl)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-semibold"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            Ver
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Modal Completo de Detalhes do Controle */}
      <AnimatePresence>
        {selectedControl && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-zinc-900 border border-zinc-800 rounded-3xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden"
            >
              {/* Header do Modal */}
              <div className="p-6 border-b border-zinc-800 flex items-center justify-between bg-zinc-950/60">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-3 py-1.5 rounded-xl">
                    {selectedControl.control_code}
                  </span>
                  <div>
                    <h2 className="text-lg font-bold text-white line-clamp-1">{selectedControl.name}</h2>
                    <div className="flex items-center gap-2 text-xs text-zinc-400 mt-0.5">
                      <span className="uppercase tracking-wider font-semibold text-emerald-400">{selectedControl.category}</span>
                      <span>•</span>
                      <span>Revisão: v{selectedControl.revision}</span>
                      <span>•</span>
                      <span>Responsável: {selectedControl.owner}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => copyToClipboard(
                      `# ${selectedControl.control_code} - ${selectedControl.name}\n\n## Descrição\n${selectedControl.description}\n\n## Rationale\n${selectedControl.rationale}\n\n## Implementação\n${selectedControl.implementation}\n\n## Validação\n${selectedControl.validation_method}`,
                      selectedControl.control_code
                    )}
                    className="p-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 hover:text-white transition-colors"
                    title="Copiar Diretriz Completa em Markdown"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setSelectedControl(null)}
                    className="p-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-white transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Abas do Modal */}
              <div className="flex items-center gap-2 px-6 pt-3 border-b border-zinc-800/80 bg-zinc-950/30 text-xs overflow-x-auto">
                <button
                  onClick={() => setActiveModalTab('overview')}
                  className={`pb-3 px-3 font-semibold border-b-2 transition-all ${
                    activeModalTab === 'overview'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Visão Geral & Rationale
                </button>
                <button
                  onClick={() => setActiveModalTab('implementation')}
                  className={`pb-3 px-3 font-semibold border-b-2 transition-all ${
                    activeModalTab === 'implementation'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Implementação & Validação
                </button>
                <button
                  onClick={() => setActiveModalTab('evidence')}
                  className={`pb-3 px-3 font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
                    activeModalTab === 'evidence'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Evidências Técnicas ({controlEvidences.length})
                </button>
                <button
                  onClick={() => setActiveModalTab('exceptions')}
                  className={`pb-3 px-3 font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
                    activeModalTab === 'exceptions'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Exceções & Riscos ({controlExceptions.length})
                </button>
                <button
                  onClick={() => setActiveModalTab('audit')}
                  className={`pb-3 px-3 font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
                    activeModalTab === 'audit'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Trilha de Auditoria ({controlAuditEvents.length})
                </button>
              </div>

              {/* Corpo do Modal */}
              <div className="p-6 overflow-y-auto flex-1 space-y-6">
                {activeModalTab === 'overview' && (
                  <div className="space-y-6">
                    {/* Metadados Rápidos */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-2xl bg-zinc-950 border border-zinc-800/80 text-xs">
                      <div>
                        <div className="text-zinc-500 font-medium">Severidade</div>
                        <div className="mt-1 font-bold capitalize text-white">{selectedControl.severity}</div>
                      </div>
                      <div>
                        <div className="text-zinc-500 font-medium">Status Operacional</div>
                        <div className="mt-1 font-bold capitalize text-emerald-400">{selectedControl.status}</div>
                      </div>
                      <div>
                        <div className="text-zinc-500 font-medium">Última Verificação</div>
                        <div className="mt-1 text-zinc-300">
                          {selectedControl.last_verified_at ? new Date(selectedControl.last_verified_at).toLocaleDateString('pt-BR') : 'Pendente'}
                        </div>
                      </div>
                      <div>
                        <div className="text-zinc-500 font-medium">Próxima Revisão</div>
                        <div className="mt-1 text-zinc-300">
                          {selectedControl.next_review_at ? new Date(selectedControl.next_review_at).toLocaleDateString('pt-BR') : 'Não agendada'}
                        </div>
                      </div>
                    </div>

                    {/* Descrição */}
                    <div>
                      <h4 className="text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2">Descrição Completa</h4>
                      <p className="text-sm text-zinc-200 leading-relaxed bg-zinc-950/60 p-4 rounded-2xl border border-zinc-800/60 whitespace-pre-wrap">
                        {selectedControl.description}
                      </p>
                    </div>

                    {/* Rationale / Justificativa */}
                    <div>
                      <h4 className="text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2">Justificativa & Risco Mitigado (Rationale)</h4>
                      <div className="text-sm text-zinc-200 leading-relaxed bg-zinc-950/60 p-4 rounded-2xl border border-zinc-800/60 flex items-start gap-3">
                        <Info className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                        <div>{selectedControl.rationale}</div>
                      </div>
                    </div>
                  </div>
                )}

                {activeModalTab === 'implementation' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between pb-2 border-b border-zinc-800">
                      <span className="text-xs text-zinc-400">
                        {isEditing ? 'Modo de Edição com Concorrência Otimista (expected_revision)' : 'Especificação Técnica'}
                      </span>
                      <button
                        onClick={() => setIsEditing(!isEditing)}
                        className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 underline"
                      >
                        {isEditing ? 'Cancelar Edição' : 'Editar Especificação'}
                      </button>
                    </div>

                    {isEditing ? (
                      <div className="space-y-4">
                        <div>
                          <label className="block text-xs font-medium text-zinc-400 mb-1">Implementação Técnica</label>
                          <textarea
                            rows={6}
                            value={editForm.implementation || ''}
                            onChange={e => setEditForm({ ...editForm, implementation: e.target.value })}
                            className="w-full p-3 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-white font-mono focus:border-emerald-500/60 focus:outline-none"
                          />
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-zinc-400 mb-1">Método Empírico de Validação</label>
                          <textarea
                            rows={4}
                            value={editForm.validation_method || ''}
                            onChange={e => setEditForm({ ...editForm, validation_method: e.target.value })}
                            className="w-full p-3 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-white font-mono focus:border-emerald-500/60 focus:outline-none"
                          />
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="block text-xs font-medium text-zinc-400 mb-1">Status</label>
                            <select
                              value={editForm.status}
                              onChange={e => setEditForm({ ...editForm, status: e.target.value as any })}
                              className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-white"
                            >
                              <option value="planned">Planejado</option>
                              <option value="in_progress">Em Progresso</option>
                              <option value="implemented">Implementado</option>
                              <option value="verified">Verificado</option>
                              <option value="exception">Exceção</option>
                              <option value="not_applicable">Não Aplicável</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-xs font-medium text-zinc-400 mb-1">Responsável</label>
                            <input
                              type="text"
                              value={editForm.owner || ''}
                              onChange={e => setEditForm({ ...editForm, owner: e.target.value })}
                              className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-white"
                            />
                          </div>
                        </div>

                        <div className="pt-2 flex justify-end">
                          <button
                            onClick={handleSaveControl}
                            disabled={isSaving}
                            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white shadow-lg shadow-emerald-950/40"
                          >
                            <Save className="w-4 h-4" />
                            {isSaving ? 'Gravando...' : `Salvar Alterações (v${selectedControl.revision} -> v${selectedControl.revision + 1})`}
                          </button>
                        </div>
                      </div>
                    ) : (
                      <>
                        <div>
                          <h4 className="text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2">Detalhamento da Implementação Técnica</h4>
                          <div className="text-xs text-zinc-200 font-mono leading-relaxed bg-zinc-950 p-4 rounded-2xl border border-zinc-800/80 whitespace-pre-wrap">
                            {selectedControl.implementation}
                          </div>
                        </div>

                        <div>
                          <h4 className="text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2">Método de Teste e Validação</h4>
                          <div className="text-xs text-zinc-200 font-mono leading-relaxed bg-zinc-950 p-4 rounded-2xl border border-zinc-800/80 whitespace-pre-wrap">
                            {selectedControl.validation_method}
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                )}

                {activeModalTab === 'evidence' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-zinc-400 uppercase tracking-wider">Evidências Registradas</h4>
                      <button
                        onClick={() => setIsCreatingEvidence(!isCreatingEvidence)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-xs font-semibold text-emerald-400 transition-colors"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Anexar Evidência
                      </button>
                    </div>

                    {isCreatingEvidence && (
                      <form onSubmit={handleCreateEvidence} className="p-4 rounded-2xl bg-zinc-950 border border-emerald-500/30 space-y-3">
                        <h5 className="text-xs font-bold text-emerald-400">Nova Evidência de Conformidade</h5>
                        <input
                          type="text"
                          placeholder="Título da evidência (ex: Relatório de Penetration Testing)"
                          value={newEvidenceTitle}
                          onChange={e => setNewEvidenceTitle(e.target.value)}
                          className="w-full p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-white"
                          required
                        />
                        <textarea
                          placeholder="Descrição do teste realizado e resultados obtidos..."
                          rows={3}
                          value={newEvidenceDesc}
                          onChange={e => setNewEvidenceDesc(e.target.value)}
                          className="w-full p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-white"
                          required
                        />
                        <div className="grid grid-cols-2 gap-3">
                          <select
                            value={newEvidenceType}
                            onChange={e => setNewEvidenceType(e.target.value)}
                            className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-white"
                          >
                            <option value="report">Relatório Técnico</option>
                            <option value="log">Log de Execução</option>
                            <option value="metric">Métrica / Telemetria</option>
                            <option value="config">Arquivo de Configuração</option>
                            <option value="screenshot">Captura / Comprovante</option>
                            <option value="code">Código / Teste</option>
                            <option value="other">Outro</option>
                          </select>
                          <input
                            type="text"
                            placeholder="Dados sanitizados ou resumo técnico..."
                            value={newEvidenceData}
                            onChange={e => setNewEvidenceData(e.target.value)}
                            className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-white"
                          />
                        </div>
                        <div className="flex justify-end gap-2 pt-2">
                          <button
                            type="button"
                            onClick={() => setIsCreatingEvidence(false)}
                            className="px-3 py-1.5 rounded-xl text-xs text-zinc-400 hover:text-white"
                          >
                            Cancelar
                          </button>
                          <button
                            type="submit"
                            className="px-4 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
                          >
                            Gravar Evidência
                          </button>
                        </div>
                      </form>
                    )}

                    {controlEvidences.length === 0 ? (
                      <div className="text-center py-10 text-zinc-500 text-xs">
                        Nenhuma evidência técnica anexada até o momento.
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {controlEvidences.map(ev => (
                          <div key={ev.id} className="p-4 rounded-2xl bg-zinc-950 border border-zinc-800/80 text-xs space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-white text-sm">{ev.title}</span>
                              <span className="font-mono text-[10px] text-zinc-500">
                                {new Date(ev.created_at).toLocaleString('pt-BR')}
                              </span>
                            </div>
                            <p className="text-zinc-300">{ev.description}</p>
                            <div className="pt-2 flex items-center justify-between border-t border-zinc-900 text-[11px] text-zinc-500">
                              <span>Tipo: {ev.evidence_type}</span>
                              <span className="font-mono text-emerald-400/80">SHA-256: {ev.hash.slice(0, 16)}...</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {activeModalTab === 'exceptions' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-zinc-400 uppercase tracking-wider">Histórico de Exceções & Riscos</h4>
                      <button
                        onClick={() => setIsCreatingException(!isCreatingException)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-xs font-semibold text-purple-400 transition-colors"
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Registrar Exceção
                      </button>
                    </div>

                    {isCreatingException && (
                      <form onSubmit={handleCreateException} className="p-4 rounded-2xl bg-zinc-950 border border-purple-500/30 space-y-3">
                        <h5 className="text-xs font-bold text-purple-400">Nova Exceção de Segurança / Risco Aceito</h5>
                        <textarea
                          placeholder="Justificativa técnica detalhada e impacto de risco aceito..."
                          rows={3}
                          value={newExceptionReason}
                          onChange={e => setNewExceptionReason(e.target.value)}
                          className="w-full p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-white"
                          required
                        />
                        <div className="grid grid-cols-2 gap-3">
                          <input
                            type="text"
                            placeholder="Aprovador (ex: Diretor de Segurança)"
                            value={newExceptionApprover}
                            onChange={e => setNewExceptionApprover(e.target.value)}
                            className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-white"
                            required
                          />
                          <select
                            value={newExceptionDays}
                            onChange={e => setNewExceptionDays(e.target.value)}
                            className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-white"
                          >
                            <option value="15">Expira em 15 dias</option>
                            <option value="30">Expira em 30 dias</option>
                            <option value="60">Expira em 60 dias</option>
                            <option value="90">Expira em 90 dias (máximo)</option>
                          </select>
                        </div>
                        <div className="flex justify-end gap-2 pt-2">
                          <button
                            type="button"
                            onClick={() => setIsCreatingException(false)}
                            className="px-3 py-1.5 rounded-xl text-xs text-zinc-400 hover:text-white"
                          >
                            Cancelar
                          </button>
                          <button
                            type="submit"
                            className="px-4 py-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-xs font-semibold text-white"
                          >
                            Aprovar Exceção
                          </button>
                        </div>
                      </form>
                    )}

                    {controlExceptions.length === 0 ? (
                      <div className="text-center py-10 text-zinc-500 text-xs">
                        Nenhuma exceção registrada para este controle.
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {controlExceptions.map(ex => (
                          <div key={ex.id} className="p-4 rounded-2xl bg-zinc-950 border border-zinc-800/80 text-xs space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-purple-300">Aprovado por: {ex.approved_by}</span>
                              <span className={`px-2 py-0.5 rounded-full font-semibold text-[10px] ${
                                ex.status === 'active' ? 'bg-purple-500/20 text-purple-300' : 'bg-emerald-500/20 text-emerald-300'
                              }`}>
                                {ex.status === 'active' ? 'Ativa' : 'Resolvida'}
                              </span>
                            </div>
                            <p className="text-zinc-300">{ex.reason}</p>
                            <div className="pt-2 flex items-center justify-between border-t border-zinc-900 text-[11px] text-zinc-500">
                              <span>Vence em: {new Date(ex.expires_at).toLocaleDateString('pt-BR')}</span>
                              {ex.status === 'active' && (
                                <button
                                  onClick={() => setResolvingExceptionId(ex.id)}
                                  className="text-xs text-emerald-400 hover:underline font-semibold"
                                >
                                  Resolver Exceção
                                </button>
                              )}
                            </div>

                            {resolvingExceptionId === ex.id && (
                              <div className="mt-3 pt-3 border-t border-zinc-800 space-y-2">
                                <input
                                  type="text"
                                  placeholder="Notas da resolução / medidas adotadas..."
                                  value={resolutionNotes}
                                  onChange={e => setResolutionNotes(e.target.value)}
                                  className="w-full p-2 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-white"
                                />
                                <div className="flex justify-end gap-2">
                                  <button
                                    onClick={() => setResolvingExceptionId(null)}
                                    className="px-2.5 py-1 text-xs text-zinc-400"
                                  >
                                    Cancelar
                                  </button>
                                  <button
                                    onClick={() => handleResolveException(ex.id)}
                                    className="px-3 py-1 rounded-lg bg-emerald-600 text-xs font-semibold text-white"
                                  >
                                    Confirmar Resolução
                                  </button>
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {activeModalTab === 'audit' && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-bold text-zinc-400 uppercase tracking-wider">Trilha Imutável de Auditoria (Append-Only)</h4>
                    {controlAuditEvents.length === 0 ? (
                      <div className="text-center py-10 text-zinc-500 text-xs">
                        Nenhum evento registrado nesta sessão.
                      </div>
                    ) : (
                      <div className="space-y-2.5">
                        {controlAuditEvents.map(evt => (
                          <div key={evt.id} className="p-3.5 rounded-xl bg-zinc-950 border border-zinc-800/60 text-xs flex flex-col gap-1">
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-emerald-400 font-bold">{evt.event_type}</span>
                              <span className="text-[10px] text-zinc-500 font-mono">
                                {new Date(evt.created_at).toLocaleString('pt-BR')}
                              </span>
                            </div>
                            <div className="text-zinc-400 text-[11px]">
                              Ator: <span className="text-zinc-200">{evt.actor}</span> • Origem: <span className="text-zinc-200">{evt.ip_origin}</span>
                            </div>
                            {evt.diff && (
                              <pre className="mt-1 p-2 rounded-lg bg-zinc-900 text-[10px] text-zinc-400 font-mono overflow-x-auto">
                                {JSON.stringify(evt.diff, null, 2)}
                              </pre>
                            )}
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

      {/* Modal de Criação de Novo Controle */}
      <AnimatePresence>
        {isCreateModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-zinc-900 border border-zinc-800 rounded-3xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden"
            >
              <div className="p-6 border-b border-zinc-800 flex items-center justify-between bg-zinc-950/60">
                <div className="flex items-center gap-3">
                  <span className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400">
                    <Plus className="w-5 h-5" />
                  </span>
                  <h3 className="text-base font-bold text-white">Novo Controle de Segurança Corporativa</h3>
                </div>
                <button onClick={() => setIsCreateModalOpen(false)} className="text-zinc-500 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <form onSubmit={handleCreateNewControl} className="p-6 overflow-y-auto space-y-4 text-xs">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block font-medium text-zinc-400 mb-1">Código do Controle (SEC-XXX)</label>
                    <input
                      type="text"
                      placeholder="ex: SEC-101"
                      value={createCode}
                      onChange={e => setCreateCode(e.target.value)}
                      className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white font-mono"
                      required
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-zinc-400 mb-1">Categoria</label>
                    <select
                      value={createCategory}
                      onChange={e => setCreateCategory(e.target.value as any)}
                      className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white"
                    >
                      <option value="rede">Rede</option>
                      <option value="trafego">Tráfego & TLS</option>
                      <option value="api">API & CORS</option>
                      <option value="autenticacao">Autenticação & MFA</option>
                      <option value="dados">Dados & LGPD</option>
                      <option value="infraestrutura">Infraestrutura</option>
                      <option value="aplicacao">Aplicação</option>
                      <option value="monitoramento">Monitoramento</option>
                      <option value="incidentes">Incidentes & DR</option>
                      <option value="governanca">Governança</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block font-medium text-zinc-400 mb-1">Nome do Controle</label>
                  <input
                    type="text"
                    placeholder="ex: Rotação Automatizada de Certificados SSL"
                    value={createName}
                    onChange={e => setCreateName(e.target.value)}
                    className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white"
                    required
                  />
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="block font-medium text-zinc-400 mb-1">Severidade</label>
                    <select
                      value={createSeverity}
                      onChange={e => setCreateSeverity(e.target.value as any)}
                      className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white"
                    >
                      <option value="critical">Crítico</option>
                      <option value="high">Alto</option>
                      <option value="medium">Médio</option>
                      <option value="low">Baixo</option>
                    </select>
                  </div>
                  <div>
                    <label className="block font-medium text-zinc-400 mb-1">Status</label>
                    <select
                      value={createStatus}
                      onChange={e => setCreateStatus(e.target.value as any)}
                      className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white"
                    >
                      <option value="planned">Planejado</option>
                      <option value="in_progress">Em Progresso</option>
                      <option value="implemented">Implementado</option>
                      <option value="verified">Verificado</option>
                      <option value="exception">Exceção</option>
                    </select>
                  </div>
                  <div>
                    <label className="block font-medium text-zinc-400 mb-1">Responsável</label>
                    <input
                      type="text"
                      value={createOwner}
                      onChange={e => setCreateOwner(e.target.value)}
                      className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white"
                    />
                  </div>
                </div>

                <div>
                  <label className="block font-medium text-zinc-400 mb-1">Descrição</label>
                  <textarea
                    rows={3}
                    placeholder="Descreva o que o controle realiza..."
                    value={createDesc}
                    onChange={e => setCreateDesc(e.target.value)}
                    className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white"
                    required
                  />
                </div>

                <div>
                  <label className="block font-medium text-zinc-400 mb-1">Justificativa & Risco Mitigado (Rationale)</label>
                  <textarea
                    rows={2}
                    placeholder="Por que este controle é essencial..."
                    value={createRationale}
                    onChange={e => setCreateRationale(e.target.value)}
                    className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white"
                    required
                  />
                </div>

                <div>
                  <label className="block font-medium text-zinc-400 mb-1">Implementação Técnica</label>
                  <textarea
                    rows={3}
                    placeholder="Instruções de como aplicar no projeto/código..."
                    value={createImplementation}
                    onChange={e => setCreateImplementation(e.target.value)}
                    className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white font-mono"
                    required
                  />
                </div>

                <div>
                  <label className="block font-medium text-zinc-400 mb-1">Método de Validação e Teste</label>
                  <input
                    type="text"
                    placeholder="Como comprovar que o controle funciona (ex: comando curl, teste unitário)"
                    value={createValidation}
                    onChange={e => setCreateValidation(e.target.value)}
                    className="w-full p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 text-white font-mono"
                    required
                  />
                </div>

                <div className="pt-4 flex justify-end gap-3 border-t border-zinc-800">
                  <button
                    type="button"
                    onClick={() => setIsCreateModalOpen(false)}
                    className="px-4 py-2 rounded-xl text-zinc-400 hover:text-white"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={isCreatingControl}
                    className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 font-semibold text-white shadow-lg shadow-emerald-950/40"
                  >
                    {isCreatingControl ? 'Cadastrando...' : 'Criar Controle'}
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Modal de Importação em Massa (Preview & Commit) */}
      <AnimatePresence>
        {isImportModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-zinc-900 border border-zinc-800 rounded-3xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden"
            >
              <div className="p-6 border-b border-zinc-800 flex items-center justify-between bg-zinc-950/60">
                <div className="flex items-center gap-3">
                  <span className="p-2 rounded-xl bg-zinc-800 text-zinc-300">
                    <UploadCloud className="w-5 h-5 text-emerald-400" />
                  </span>
                  <div>
                    <h3 className="text-base font-bold text-white">Importação em Massa (Preview & Commit)</h3>
                    <p className="text-xs text-zinc-400">Validação em duas etapas: análise prévia com diff sem gravação, commit sob confirmação.</p>
                  </div>
                </div>
                <button onClick={() => { setIsImportModalOpen(false); setImportPreviewResult(null); }} className="text-zinc-500 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-6 overflow-y-auto space-y-4 text-xs">
                <div>
                  <label className="block font-medium text-zinc-400 mb-1">
                    Cole o JSON com a lista de controles (Array de objetos):
                  </label>
                  <textarea
                    rows={8}
                    placeholder='[{"control_code": "SEC-001", "name": "...", "category": "rede", "description": "...", "rationale": "...", "implementation": "...", "validation_method": "..."}]'
                    value={importJsonText}
                    onChange={e => setImportJsonText(e.target.value)}
                    className="w-full p-3 rounded-xl bg-zinc-950 border border-zinc-800 text-white font-mono focus:border-emerald-500/50 focus:outline-none"
                  />
                </div>

                <div className="flex justify-between items-center">
                  <button
                    onClick={handleImportPreview}
                    disabled={isProcessingImport || !importJsonText.trim()}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white font-semibold transition-all"
                  >
                    <Eye className="w-4 h-4 text-emerald-400" />
                    {isProcessingImport ? 'Analisando...' : '1. Gerar Prévia (Preview)'}
                  </button>

                  {importPreviewResult?.ok && (
                    <button
                      onClick={handleImportCommit}
                      disabled={isProcessingImport}
                      className="inline-flex items-center gap-2 px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold shadow-lg shadow-emerald-950/40 transition-all"
                    >
                      <Check className="w-4 h-4" />
                      2. Confirmar Gravação (Commit)
                    </button>
                  )}
                </div>

                {/* Exibição do Resultado da Prévia */}
                {importPreviewResult && (
                  <div className={`p-4 rounded-2xl border text-xs space-y-3 ${
                    importPreviewResult.ok
                      ? 'bg-emerald-950/20 border-emerald-500/30'
                      : 'bg-rose-950/20 border-rose-500/30'
                  }`}>
                    <div className="font-bold text-sm flex items-center justify-between">
                      <span className={importPreviewResult.ok ? 'text-emerald-300' : 'text-rose-300'}>
                        {importPreviewResult.ok ? 'Prévia Aprovada com Sucesso' : 'Falha na Validação do Lote'}
                      </span>
                      <span className="text-zinc-400 font-normal">
                        Total: {importPreviewResult.total_items} controles
                      </span>
                    </div>
                    <p className="text-zinc-300">{importPreviewResult.summary}</p>

                    {importPreviewResult.ok ? (
                      <div className="grid grid-cols-3 gap-2 pt-2 border-t border-zinc-800 text-center font-semibold">
                        <div className="bg-zinc-900/60 p-2 rounded-lg text-emerald-400">
                          {importPreviewResult.to_create_count} Novos
                        </div>
                        <div className="bg-zinc-900/60 p-2 rounded-lg text-amber-400">
                          {importPreviewResult.to_update_count} Atualizações
                        </div>
                        <div className="bg-zinc-900/60 p-2 rounded-lg text-zinc-400">
                          {importPreviewResult.unchanged_count} Inalterados
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-1.5 pt-2 border-t border-rose-500/20">
                        {importPreviewResult.validation_errors.map((err: any, i: number) => (
                          <div key={i} className="text-rose-400 font-mono text-[11px]">
                            Item #{err.index + 1} ({err.control_code || 'sem código'}): {err.errors.join(', ')}
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
    </div>
  );
}
