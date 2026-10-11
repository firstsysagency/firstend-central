import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Lock, 
  Search, 
  Download, 
  FileText, 
  RefreshCw, 
  Eye, 
  ShieldAlert, 
  AlertTriangle, 
  Info, 
  X, 
  Copy, 
  Check, 
  Terminal,
  Database
} from 'lucide-react';
import { 
  type AuditLogEntry, 
  type AuditCategory, 
  type AuditSeverity, 
  getAuditLogs, 
  exportAuditLogsAsCSV, 
  exportAuditLogsAsJSON 
} from '../../lib/audit';
import { getPostgresStatus } from '../../lib/postgresAudit';

interface AuditTabProps {
  onShowToast: (msg: string) => void;
}

export default function AuditTab({ onShowToast }: AuditTabProps) {
  const [logs, setLogs] = useState<AuditLogEntry[]>(() => getAuditLogs());
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<AuditCategory | 'all'>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<AuditSeverity | 'all'>('all');
  const [inspectingLog, setInspectingLog] = useState<AuditLogEntry | null>(null);
  const pgStatus = getPostgresStatus();

  const refreshLogs = () => {
    setLogs(getAuditLogs());
    onShowToast('Trilha de auditoria sincronizada.');
  };

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (selectedCategory !== 'all' && log.category !== selectedCategory) {
        return false;
      }
      if (selectedSeverity !== 'all' && log.severity !== selectedSeverity) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesDesc = log.description.toLowerCase().includes(q);
        const matchesActor = log.actor.toLowerCase().includes(q);
        const matchesAction = log.action.toLowerCase().includes(q);
        const matchesIp = log.ipAddress.toLowerCase().includes(q);
        if (!matchesDesc && !matchesActor && !matchesAction && !matchesIp) {
          return false;
        }
      }
      return true;
    });
  }, [logs, selectedCategory, selectedSeverity, searchQuery]);

  const handleExportCSV = () => {
    exportAuditLogsAsCSV(filteredLogs);
    onShowToast(`Exportando ${filteredLogs.length} registros em CSV.`);
  };

  const handleExportJSON = () => {
    exportAuditLogsAsJSON(filteredLogs);
    onShowToast(`Exportando ${filteredLogs.length} registros em JSON.`);
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Cabeçalho */}
      <div className="glass rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-border">
          <div>
            <h3 className="text-xl font-bold text-foreground">Trilha de Auditoria e Logs</h3>
            <p className="text-zinc-400 text-sm mt-1">
              Registro contínuo e imutável de eventos criptográficos, acessos e operações sensíveis no sistema.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              type="button"
              onClick={refreshLogs}
              className="p-2.5 rounded-xl border border-border bg-white/5 hover:bg-white/10 text-zinc-300 hover:text-white transition-colors cursor-pointer"
              title="Recarregar Logs"
            >
              <RefreshCw size={15} />
            </button>
            <button
              type="button"
              onClick={handleExportCSV}
              className="px-3.5 py-2.5 rounded-xl border border-border bg-white/5 hover:bg-white/10 text-zinc-300 hover:text-white text-xs font-semibold transition-colors flex items-center gap-2 cursor-pointer"
            >
              <Download size={14} />
              <span>Exportar CSV</span>
            </button>
            <button
              type="button"
              onClick={handleExportJSON}
              className="px-3.5 py-2.5 rounded-xl border border-border bg-white/5 hover:bg-white/10 text-zinc-300 hover:text-white text-xs font-semibold transition-colors flex items-center gap-2 cursor-pointer"
            >
              <FileText size={14} />
              <span>Exportar JSON</span>
            </button>
          </div>
        </div>

        {/* Card de Status do Banco PostgreSQL e RLS */}
        <div className="mt-5 p-4 rounded-xl bg-secondary/40 border border-emerald-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 flex-shrink-0">
              <Database size={18} />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-foreground">PostgreSQL: RLS Ativo e Append-Only</span>
                <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-mono flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  Conectado
                </span>
              </div>
              <span className="text-zinc-400 text-[11px] mt-0.5">
                Host: <code className="text-zinc-300 font-mono">{pgStatus.host}</code> • Banco: <code className="text-primary font-mono">{pgStatus.databaseName}</code> • Isolamento Multi-Tenant Garantido
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold self-start sm:self-auto">
            <Lock size={12} />
            <span>Camada Backend Segura</span>
          </div>
        </div>

        {/* Filtros e Busca */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 pt-6">
          <div className="md:col-span-6 relative">
            <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Buscar por ator, ação, IP ou descrição..."
              className="w-full bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl pl-10 pr-4 py-2 text-foreground text-xs focus:outline-none focus:ring-2 transition-all"
            />
          </div>

          <div className="md:col-span-3">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value as AuditCategory | 'all')}
              className="w-full bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-3 py-2 text-foreground text-xs focus:outline-none focus:ring-2 transition-all cursor-pointer"
            >
              <option value="all">Todas as Categorias</option>
              <option value="keys">Chaves e Rotação</option>
              <option value="auth">Autenticação & MFA</option>
              <option value="members">Gestão de Membros</option>
              <option value="notifications">Notificações / Webhooks</option>
              <option value="mcp">Agente MCP (ChatGPT)</option>
              <option value="system">Segurança e Sistema</option>
            </select>
          </div>

          <div className="md:col-span-3">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value as AuditSeverity | 'all')}
              className="w-full bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-3 py-2 text-foreground text-xs focus:outline-none focus:ring-2 transition-all cursor-pointer"
            >
              <option value="all">Todas as Severidades</option>
              <option value="info">Informação (Info)</option>
              <option value="warning">Alerta (Warning)</option>
              <option value="critical">Crítico (Critical)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Tabela de Logs de Auditoria */}
      <div className="glass rounded-2xl overflow-hidden border border-border">
        <div className="p-4 border-b border-border bg-secondary/30 flex items-center justify-between text-xs text-zinc-400">
          <span>{filteredLogs.length} eventos registrados</span>
          <span>Armazenamento criptografado (Redaction de segredos ativo)</span>
        </div>

        {filteredLogs.length === 0 ? (
          <div className="p-12 flex flex-col items-center justify-center text-center text-zinc-500">
            <Lock size={32} className="mb-3 text-zinc-600" />
            <p className="text-sm font-medium">Nenhum evento corresponde aos filtros aplicados.</p>
            <span className="text-xs mt-1">Tente ajustar a busca ou limpar as restrições de severidade.</span>
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {filteredLogs.map((log) => (
              <div 
                key={log.id} 
                className="p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors"
              >
                {/* Linha Principal */}
                <div className="flex items-start gap-3.5 flex-1">
                  <div className="mt-0.5">
                    <SeverityIcon severity={log.severity} />
                  </div>
                  <div className="flex flex-col gap-1 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono font-semibold text-primary">{log.action}</span>
                      <SeverityBadge severity={log.severity} />
                      <CategoryBadge category={log.category} />
                      <span className="text-[11px] text-zinc-500 font-mono">IP: {log.ipAddress}</span>
                    </div>
                    <p className="text-xs text-foreground font-medium leading-relaxed mt-0.5">
                      {log.description}
                    </p>
                    <div className="flex items-center gap-2 text-[11px] text-zinc-400 font-mono">
                      <span>{log.formattedDate}</span>
                      <span>•</span>
                      <span>Ator: <strong className="text-zinc-300">{log.actor}</strong></span>
                    </div>
                  </div>
                </div>

                {/* Ação de Inspecionar */}
                <div className="flex items-center justify-end">
                  <button
                    type="button"
                    onClick={() => setInspectingLog(log)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-zinc-300 hover:text-white bg-white/5 hover:bg-white/10 border border-border transition-colors cursor-pointer"
                  >
                    <Eye size={13} />
                    <span>Detalhes</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Modal Inspecionar Evento */}
      <AnimatePresence>
        {inspectingLog && (
          <AuditDetailModal
            log={inspectingLog}
            onClose={() => setInspectingLog(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function SeverityIcon({ severity }: { severity: AuditSeverity }) {
  switch (severity) {
    case 'info':
      return <Info size={16} className="text-primary flex-shrink-0" />;
    case 'warning':
      return <AlertTriangle size={16} className="text-amber-400 flex-shrink-0" />;
    case 'critical':
      return <ShieldAlert size={16} className="text-rose-400 flex-shrink-0" />;
  }
}

function SeverityBadge({ severity }: { severity: AuditSeverity }) {
  switch (severity) {
    case 'info':
      return (
        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
          Info
        </span>
      );
    case 'warning':
      return (
        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
          Warning
        </span>
      );
    case 'critical':
      return (
        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 animate-pulse">
          Crítico
        </span>
      );
  }
}

function CategoryBadge({ category }: { category: AuditCategory }) {
  return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-secondary text-zinc-300 border border-border">
      {category}
    </span>
  );
}

function AuditDetailModal({
  log,
  onClose
}: {
  log: AuditLogEntry;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const formattedJson = JSON.stringify(
    {
      id: log.id,
      timestamp: log.timestamp,
      action: log.action,
      category: log.category,
      severity: log.severity,
      actor: log.actor,
      ipAddress: log.ipAddress,
      description: log.description,
      details: log.details || {}
    },
    null,
    2
  );

  const handleCopy = () => {
    navigator.clipboard.writeText(formattedJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md cursor-pointer"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.9, y: 20 }}
        className="glass max-w-2xl w-full rounded-2xl p-6 border border-border shadow-2xl relative overflow-hidden cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Terminal size={20} />
            </div>
            <div>
              <h4 className="text-xl font-bold text-foreground">Metadados do Evento de Auditoria</h4>
              <p className="text-xs text-zinc-400 font-mono">{log.id}</p>
            </div>
          </div>
          <button 
            type="button"
            onClick={onClose}
            className="text-zinc-400 hover:text-foreground p-1.5 rounded-lg hover:bg-white/5 transition-colors cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        <div className="flex flex-col gap-4 mt-5">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-secondary/50 rounded-xl border border-border flex flex-col">
              <span className="text-[11px] text-zinc-400">Ação</span>
              <span className="text-xs font-mono font-bold text-primary mt-0.5 truncate">{log.action}</span>
            </div>
            <div className="p-3 bg-secondary/50 rounded-xl border border-border flex flex-col">
              <span className="text-[11px] text-zinc-400">Severidade</span>
              <span className="text-xs font-semibold capitalize text-foreground mt-0.5">{log.severity}</span>
            </div>
            <div className="p-3 bg-secondary/50 rounded-xl border border-border flex flex-col">
              <span className="text-[11px] text-zinc-400">Ator</span>
              <span className="text-xs font-mono text-zinc-200 mt-0.5 truncate">{log.actor}</span>
            </div>
            <div className="p-3 bg-secondary/50 rounded-xl border border-border flex flex-col">
              <span className="text-[11px] text-zinc-400">Endereço IP</span>
              <span className="text-xs font-mono text-zinc-200 mt-0.5">{log.ipAddress}</span>
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-zinc-300">Payload Estruturado (JSON)</label>
              <button
                type="button"
                onClick={handleCopy}
                className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white transition-colors cursor-pointer"
              >
                {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                <span>{copied ? 'Copiado!' : 'Copiar JSON'}</span>
              </button>
            </div>
            <pre className="p-4 bg-black/50 border border-border rounded-xl text-xs font-mono text-zinc-300 overflow-x-auto max-h-64 leading-relaxed">
              {formattedJson}
            </pre>
          </div>

          <div className="flex justify-end pt-3 border-t border-border mt-1">
            <button
              type="button"
              onClick={onClose}
              className="bg-secondary hover:bg-white/10 text-foreground px-5 py-2 rounded-xl text-sm font-semibold transition-colors border border-border cursor-pointer"
            >
              Fechar
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

