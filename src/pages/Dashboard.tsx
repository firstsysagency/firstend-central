import React, { useRef, useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { 
  Key, 
  ShieldAlert, 
  ShieldCheck, 
  Clock, 
  MoreVertical, 
  Plus, 
  Settings as SettingsIcon, 
  Trash2, 
  AlertTriangle, 
  CheckCircle2, 
  X, 
  Lock, 
  Server, 
  FileText 
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { 
  type Connection, 
  getStoredConnections, 
  updateConnection, 
  deleteConnection,
  fetchBackendConnections
} from '../lib/connections';

gsap.registerPlugin(useGSAP);

export default function Dashboard() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [connections, setConnections] = useState<Connection[]>(() => getStoredConnections());
  const [openMenuId, setOpenMenuId] = useState<string | null>(null);
  
  // Modais centrais
  const [deletingConnection, setDeletingConnection] = useState<Connection | null>(null);
  const [configuringConnection, setConfiguringConnection] = useState<Connection | null>(null);
  
  // Feedback toast
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  
  // Sincroniza conexões ativas do backend (variáveis de ambiente do Coolify)
  useEffect(() => {
    fetchBackendConnections().then((conns) => {
      if (conns && conns.length > 0) {
        setConnections(conns);
      }
    });
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 3500);
  };

  useGSAP(() => {
    gsap.from('.stat-card', {
      y: 20,
      opacity: 0,
      stagger: 0.1,
      duration: 0.6,
      ease: 'power3.out',
      clearProps: 'all'
    });
    gsap.from('.conn-row', {
      x: -20,
      opacity: 0,
      stagger: 0.05,
      duration: 0.5,
      ease: 'power2.out',
      delay: 0.3,
      clearProps: 'all'
    });
  }, { scope: containerRef, dependencies: [connections.length] });

  // Métricas calculadas em tempo real
  const totalCount = connections.length;
  const activeCount = connections.filter(c => c.status === 'active').length;
  const problemCount = connections.filter(c => c.status !== 'active').length;

  const handleConfirmDelete = () => {
    if (!deletingConnection) return;
    const updated = deleteConnection(deletingConnection.id);
    setConnections(updated);
    showToast(`Conexão "${deletingConnection.name}" revogada e excluída com sucesso.`);
    setDeletingConnection(null);
  };

  const handleSaveConfiguration = (updatedData: Partial<Connection>) => {
    if (!configuringConnection) return;
    const updated = updateConnection(configuringConnection.id, updatedData);
    setConnections(updated);
    showToast(`Configurações de "${updatedData.name || configuringConnection.name}" salvas com sucesso.`);
    setConfiguringConnection(null);
  };

  const handleToggleStatus = (conn: Connection) => {
    const nextStatus: 'active' | 'revoked' = conn.status === 'active' ? 'revoked' : 'active';
    const updated = updateConnection(conn.id, { status: nextStatus });
    setConnections(updated);
    if (nextStatus === 'active') {
      showToast(`Chave "${conn.name}" ativada.`);
    } else {
      showToast(`Chave "${conn.name}" desativada (bloqueada para uso).`);
    }
  };

  return (
    <div ref={containerRef} className="flex flex-col gap-8 max-w-6xl mx-auto relative">
      {/* Toast flutuante de notificação */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div 
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            className="fixed top-6 right-6 z-50 flex items-center gap-3 bg-secondary/90 border border-border backdrop-blur-md px-4 py-3 rounded-xl shadow-2xl text-foreground text-sm font-medium"
          >
            <CheckCircle2 size={18} className="text-emerald-400 flex-shrink-0" />
            <span>{toastMessage}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Cabeçalho */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold text-foreground tracking-tight">Dashboard</h2>
          <p className="text-zinc-400 mt-2">Visão geral das chaves e conexões da Zatten.</p>
        </div>
        <Link to="/new" className="bg-primary hover:bg-primary/90 text-primary-foreground px-5 py-2.5 rounded-xl flex items-center gap-2 font-medium transition-colors w-fit">
          <Plus size={18} />
          Nova Conexão
        </Link>
      </div>

      {/* Métricas */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatCard title="Total de Conexões" value={String(totalCount)} icon={<Key size={20} className="text-blue-400" />} />
        <StatCard title="Conexões Ativas" value={String(activeCount)} icon={<ShieldCheck size={20} className="text-emerald-400" />} />
        <StatCard title="Com Problemas / Revogadas" value={String(problemCount)} icon={<ShieldAlert size={20} className="text-rose-400" />} />
      </div>

      {/* Tabela de Conexões */}
      <div className="mt-4">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold">Conexões Cadastradas</h3>
          <span className="text-xs text-zinc-500 font-mono">
            {totalCount} {totalCount === 1 ? 'chave registrada' : 'chaves registradas'}
          </span>
        </div>

        {connections.length === 0 ? (
          <div className="glass rounded-2xl p-12 text-center flex flex-col items-center justify-center gap-4">
            <div className="w-12 h-12 rounded-full bg-secondary flex items-center justify-center text-zinc-500 border border-border">
              <Key size={22} />
            </div>
            <div>
              <p className="font-semibold text-foreground text-lg">Nenhuma conexão cadastrada</p>
              <p className="text-zinc-400 text-sm mt-1">Crie sua primeira chave de conexão Zatten de forma segura e criptografada.</p>
            </div>
            <Link to="/new" className="mt-2 bg-primary hover:bg-primary/90 text-primary-foreground px-5 py-2.5 rounded-xl flex items-center gap-2 font-medium transition-colors">
              <Plus size={18} />
              Adicionar Conexão
            </Link>
          </div>
        ) : (
          <div className="glass rounded-2xl overflow-visible">
            <div className="grid grid-cols-12 gap-4 p-4 border-b border-border text-sm font-medium text-zinc-400 items-center">
              <div className="col-span-1 text-center">Ativar</div>
              <div className="col-span-4">Nome / ID</div>
              <div className="col-span-3">Status</div>
              <div className="col-span-3">Último Uso</div>
              <div className="col-span-1 text-right">Ações</div>
            </div>
            <div className="divide-y divide-border/50">
              {connections.map((conn) => (
                <ConnectionRow 
                  key={conn.id}
                  connection={conn}
                  isOpen={openMenuId === conn.id}
                  onToggle={() => setOpenMenuId(openMenuId === conn.id ? null : conn.id)}
                  onClose={() => setOpenMenuId(null)}
                  onToggleStatus={() => handleToggleStatus(conn)}
                  onConfigure={() => {
                    setOpenMenuId(null);
                    setConfiguringConnection(conn);
                  }}
                  onDelete={() => {
                    setOpenMenuId(null);
                    setDeletingConnection(conn);
                  }}
                />
              ))}
            </div>
          </div>
        )}
      </div>

      {/* POP-UP CENTRAL: Confirmação de Exclusão / Revogação */}
      <AnimatePresence>
        {deletingConnection && (
          <DeleteConfirmModal 
            connection={deletingConnection}
            onClose={() => setDeletingConnection(null)}
            onConfirm={handleConfirmDelete}
          />
        )}
      </AnimatePresence>

      {/* POP-UP CENTRAL: Configuração da Chave / Conexão */}
      <AnimatePresence>
        {configuringConnection && (
          <ConfigureModal 
            connection={configuringConnection}
            onClose={() => setConfiguringConnection(null)}
            onSave={handleSaveConfiguration}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function StatCard({ title, value, icon }: { title: string; value: string; icon: React.ReactNode }) {
  return (
    <div className="stat-card glass p-6 rounded-2xl relative overflow-hidden group">
      <div className="absolute -right-6 -top-6 w-24 h-24 bg-primary/10 rounded-full blur-2xl group-hover:bg-primary/20 transition-all duration-500" />
      <div className="flex items-center justify-between mb-4">
        <span className="text-zinc-400 font-medium">{title}</span>
        <div className="w-10 h-10 rounded-full bg-secondary flex items-center justify-center border border-border">
          {icon}
        </div>
      </div>
      <div className="text-4xl font-bold text-foreground">{value}</div>
    </div>
  );
}

function ConnectionRow({ 
  connection, 
  isOpen, 
  onToggle, 
  onClose,
  onToggleStatus,
  onConfigure, 
  onDelete 
}: { 
  connection: Connection;
  isOpen: boolean; 
  onToggle: () => void;
  onClose: () => void;
  onToggleStatus: () => void;
  onConfigure: () => void;
  onDelete: () => void;
}) {
  const menuRef = useRef<HTMLDivElement>(null);
  const isActive = connection.status === 'active';

  useEffect(() => {
    if (!isOpen) return;

    function handlePointerDown(e: MouseEvent | TouchEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    }

    // Registrar com timeout de 0ms para não disparar no clique que acabou de abrir
    const timer = setTimeout(() => {
      document.addEventListener('mousedown', handlePointerDown);
      document.addEventListener('touchstart', handlePointerDown);
    }, 0);

    return () => {
      clearTimeout(timer);
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('touchstart', handlePointerDown);
    };
  }, [isOpen, onClose]);

  const statusColors: Record<string, string> = {
    active: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20',
    revoked: 'text-rose-400 bg-rose-400/10 border-rose-400/20',
    invalid: 'text-amber-400 bg-amber-400/10 border-amber-400/20',
    paused: 'text-zinc-400 bg-zinc-400/10 border-zinc-400/20'
  };
  
  const statusLabels: Record<string, string> = {
    active: 'Ativa',
    revoked: 'Desligada',
    invalid: 'Inválida',
    paused: 'Pausada'
  };

  return (
    <div className={`conn-row grid grid-cols-12 gap-4 p-5 items-center hover:bg-white/[0.02] transition-colors relative ${isOpen ? 'z-30' : 'z-10'} ${!isActive ? 'opacity-75' : ''}`}>
      {/* Coluna 1: Toggle Switch iPhone (iOS Style) */}
      <div className="col-span-1 flex items-center justify-center">
        <button
          type="button"
          role="switch"
          aria-checked={isActive}
          onClick={(e) => {
            e.stopPropagation();
            onToggleStatus();
          }}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-300 ease-in-out focus:outline-none focus:ring-2 focus:ring-emerald-500/50 ${
            isActive ? 'bg-[#34C759]' : 'bg-zinc-700/80 hover:bg-zinc-600'
          }`}
          title={isActive ? 'Chave ativada (clique para desligar)' : 'Chave desativada (clique para ligar)'}
        >
          <span
            aria-hidden="true"
            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-300 ease-in-out ${
              isActive ? 'translate-x-5' : 'translate-x-0'
            }`}
          />
        </button>
      </div>

      {/* Coluna 2: Nome / ID */}
      <div className="col-span-4 flex flex-col">
        <div className="flex items-center gap-2">
          <span className={`font-semibold transition-colors ${isActive ? 'text-foreground' : 'text-zinc-400'}`}>
            {connection.name}
          </span>
          {!isActive && (
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
              Bloqueada
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-1">
          <span className="text-xs text-zinc-500 font-mono">{connection.id}</span>
          <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
            {connection.environment}
          </span>
          {connection.source === 'coolify_env' && (
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 flex items-center gap-1" title="Chave protegida via Variável de Ambiente no Coolify">
              <Server size={10} /> Coolify Env
            </span>
          )}
        </div>
      </div>

      {/* Coluna 3: Status */}
      <div className="col-span-3">
        <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${statusColors[connection.status]}`}>
          {statusLabels[connection.status]}
        </span>
      </div>

      {/* Coluna 4: Último Uso */}
      <div className="col-span-3 flex items-center gap-2 text-sm text-zinc-400">
        <Clock size={14} />
        {connection.lastUsed}
      </div>

      {/* Coluna 5: Ações */}
      <div ref={menuRef} className="col-span-1 flex justify-end relative">
        <button 
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors cursor-pointer ${
            isOpen ? 'bg-secondary text-foreground' : 'text-zinc-400 hover:bg-secondary hover:text-foreground'
          }`}
          title="Opções da chave"
          aria-expanded={isOpen}
        >
          <MoreVertical size={16} />
        </button>

        <AnimatePresence>
          {isOpen && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: -10 }}
              transition={{ duration: 0.15 }}
              className="absolute right-0 top-10 bg-[#18181b] border border-zinc-700/80 rounded-xl p-1.5 z-50 min-w-[190px] shadow-2xl pointer-events-auto"
            >
              <button 
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onConfigure();
                }}
                className="flex items-center gap-2 w-full px-3 py-2.5 text-sm text-zinc-300 hover:text-foreground hover:bg-white/10 rounded-lg transition-colors text-left cursor-pointer"
              >
                <SettingsIcon size={15} className="text-zinc-400" />
                Configurar
              </button>
              <button 
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete();
                }}
                className="flex items-center gap-2 w-full px-3 py-2.5 text-sm text-rose-400 hover:text-rose-300 hover:bg-rose-500/15 rounded-lg transition-colors mt-1 text-left cursor-pointer"
              >
                <Trash2 size={15} />
                Excluir/Revogar
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

// Modal Central de Confirmação de Exclusão
function DeleteConfirmModal({
  connection,
  onClose,
  onConfirm
}: {
  connection: Connection;
  onClose: () => void;
  onConfirm: () => void;
}) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md cursor-pointer"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.9, y: 20 }}
        transition={{ type: 'spring', damping: 25, stiffness: 300 }}
        className="glass max-w-lg w-full rounded-2xl p-6 border border-rose-500/30 shadow-2xl relative overflow-hidden cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center flex-shrink-0 text-rose-400">
            <AlertTriangle size={24} />
          </div>
          <div className="flex-1">
            <h4 className="text-xl font-bold text-foreground">Confirmar Exclusão e Revogação</h4>
            <p className="text-zinc-400 text-sm mt-2 leading-relaxed">
              Você tem certeza que deseja excluir e revogar a conexão{' '}
              <strong className="text-foreground">{connection.name}</strong>{' '}
              (<span className="font-mono text-zinc-300">{connection.id}</span>)?
            </p>
          </div>
          <button 
            type="button"
            onClick={onClose}
            className="text-zinc-400 hover:text-foreground p-1 rounded-lg hover:bg-white/5 transition-colors cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        <div className="mt-5 p-3.5 bg-rose-500/5 rounded-xl border border-rose-500/15 text-xs text-rose-300 leading-relaxed">
          <strong>Atenção:</strong> Esta ação é irreversível. A chave de API no cofre será imediatamente revogada e qualquer integração em execução perderá o acesso à plataforma Zatten.
        </div>

        <div className="mt-6 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2.5 rounded-xl text-sm font-medium text-zinc-300 hover:text-foreground hover:bg-white/5 border border-border transition-colors cursor-pointer"
          >
            Cancelar
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="bg-rose-500 hover:bg-rose-600 text-white px-5 py-2.5 rounded-xl text-sm font-medium transition-colors shadow-lg shadow-rose-500/20 flex items-center gap-2 active:scale-95 cursor-pointer"
          >
            <Trash2 size={16} />
            Sim, Revogar e Excluir
          </button>
        </div>
      </motion.div>
    </div>
  );
}

// Modal Central de Configuração da Chave
function ConfigureModal({
  connection,
  onClose,
  onSave
}: {
  connection: Connection;
  onClose: () => void;
  onSave: (data: Partial<Connection>) => void;
}) {
  const [name, setName] = useState(connection.name);
  const [environment, setEnvironment] = useState(connection.environment);
  const [status, setStatus] = useState(connection.status);
  const [description, setDescription] = useState(connection.description || '');

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave({
      name,
      environment,
      status,
      description
    });
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
        transition={{ type: 'spring', damping: 25, stiffness: 300 }}
        className="glass max-w-xl w-full rounded-2xl p-6 border border-border shadow-2xl relative overflow-hidden cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <SettingsIcon size={20} />
            </div>
            <div>
              <h4 className="text-xl font-bold text-foreground">Configurar Conexão</h4>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">{connection.id}</p>
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

        <form onSubmit={handleSubmit} className="flex flex-col gap-5 mt-5">
          {/* Nome da Conexão */}
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-zinc-300 flex items-center gap-2">
              <FileText size={15} className="text-zinc-400" />
              Nome da Conexão
            </label>
            <input 
              type="text" 
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground focus:outline-none focus:ring-2 transition-all text-sm"
              placeholder="Ex: Lavínia — Atendimento"
            />
          </div>

          {/* Grid de Ambiente e Status */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                <Server size={15} className="text-zinc-400" />
                Ambiente de Execução
              </label>
              <select
                value={environment}
                onChange={(e) => setEnvironment(e.target.value as 'production' | 'staging' | 'development')}
                className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground focus:outline-none focus:ring-2 transition-all text-sm cursor-pointer"
              >
                <option value="production">Produção (Live)</option>
                <option value="staging">Homologação (Staging)</option>
                <option value="development">Desenvolvimento (Dev)</option>
              </select>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                <ShieldCheck size={15} className="text-zinc-400" />
                Status da Chave
              </label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as 'active' | 'revoked' | 'invalid')}
                className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground focus:outline-none focus:ring-2 transition-all text-sm cursor-pointer"
              >
                <option value="active">Ativa</option>
                <option value="revoked">Revogada / Pausada</option>
                <option value="invalid">Inválida</option>
              </select>
            </div>
          </div>

          {/* Proteção de Origem e Restrição CORS (Exclusiva desta Aplicação Web) */}
          <div className="p-4 bg-emerald-500/10 rounded-xl border border-emerald-500/20 flex items-start gap-3">
            <ShieldCheck size={18} className="text-emerald-400 flex-shrink-0 mt-0.5" />
            <div className="flex flex-col gap-1">
              <span className="text-xs font-semibold text-emerald-300">Proteção de Origem CORS Ativa (Exclusivo deste Painel)</span>
              <p className="text-xs text-zinc-400 leading-relaxed">
                As chamadas de automação e APIs vinculadas a esta conexão são permitidas <strong>exclusivamente a partir desta aplicação web</strong>. Qualquer requisição originada de outro domínio ou aplicação externa é bloqueada pelas políticas de CORS do backend.
              </p>
            </div>
          </div>

          {/* Descrição / Notas */}
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-zinc-300">Finalidade / Notas Internas</label>
            <textarea 
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground focus:outline-none focus:ring-2 transition-all text-sm resize-none"
              placeholder="Descreva o propósito desta integração..."
            />
          </div>

          {/* Aviso de Imutabilidade da Chave Secreta */}
          <div className="p-3 bg-primary/10 rounded-xl border border-primary/20 flex items-start gap-3">
            <Lock size={16} className="text-primary flex-shrink-0 mt-0.5" />
            <p className="text-xs text-primary-foreground/80 leading-relaxed">
              <strong>Regra de Imutabilidade:</strong> A chave secreta criptografada é protegida no cofre e não pode ser revelada ou editada após o cadastro. Para alterar a chave de API, revogue esta conexão e crie uma nova.
            </p>
          </div>

          {/* Ações */}
          <div className="mt-2 flex items-center justify-end gap-3 pt-3 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl text-sm font-medium text-zinc-300 hover:text-foreground hover:bg-white/5 border border-border transition-colors cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="bg-primary hover:bg-primary/90 text-primary-foreground px-5 py-2.5 rounded-xl text-sm font-medium transition-colors shadow-lg shadow-primary/20 active:scale-95 cursor-pointer"
            >
              Salvar Alterações
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}


