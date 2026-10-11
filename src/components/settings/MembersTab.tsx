import { useState, useRef, useEffect, type FormEvent } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Users, 
  UserPlus, 
  ShieldCheck, 
  Clock, 
  MoreVertical, 
  Trash2, 
  Edit3, 
  Send, 
  UserX, 
  UserCheck, 
  X, 
  AlertTriangle,
  HelpCircle,
  Mail,
  Shield
} from 'lucide-react';
import { 
  type Member, 
  type MemberRole, 
  getMembers, 
  inviteMember, 
  updateMemberRole, 
  toggleMemberStatus, 
  resendInvite, 
  removeMember,
  getRoleDescription
} from '../../lib/members';

interface MembersTabProps {
  onShowToast: (msg: string) => void;
}

export default function MembersTab({ onShowToast }: MembersTabProps) {
  const [members, setMembers] = useState<Member[]>(() => getMembers());
  const [isInviteModalOpen, setIsInviteModalOpen] = useState(false);
  const [editingMember, setEditingMember] = useState<Member | null>(null);
  const [memberToRemove, setMemberToRemove] = useState<Member | null>(null);
  const [activeDropdownId, setActiveDropdownId] = useState<string | null>(null);

  const refreshMembers = () => {
    setMembers(getMembers());
  };

  const handleToggleStatus = (member: Member) => {
    const res = toggleMemberStatus(member.id);
    if (res.success) {
      refreshMembers();
      onShowToast(`Status de ${member.name} alterado para ${res.newStatus === 'suspended' ? 'Suspenso' : 'Ativo'}.`);
    } else if (res.error) {
      onShowToast(res.error);
    }
    setActiveDropdownId(null);
  };

  const handleResendInvite = (member: Member) => {
    const res = resendInvite(member.id);
    if (res.success) {
      onShowToast(`Convite de acesso reenviado para ${member.email}.`);
    }
    setActiveDropdownId(null);
  };

  const handleConfirmRemove = () => {
    if (!memberToRemove) return;
    const res = removeMember(memberToRemove.id);
    if (res.success) {
      refreshMembers();
      onShowToast(`Membro ${memberToRemove.name} removido da organização.`);
    } else if (res.error) {
      onShowToast(res.error);
    }
    setMemberToRemove(null);
  };

  // Métricas
  const totalCount = members.length;
  const adminCount = members.filter(m => m.role === 'admin' || m.role === 'owner').length;
  const pendingCount = members.filter(m => m.status === 'invited').length;

  return (
    <div className="flex flex-col gap-6">
      {/* Cabeçalho e Métricas */}
      <div className="glass rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-border">
          <div>
            <h3 className="text-xl font-bold text-foreground">Membros e Acessos</h3>
            <p className="text-zinc-400 text-sm mt-1">
              Controle quem tem acesso à central de chaves e defina papéis granulares de autorização.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setIsInviteModalOpen(true)}
            className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-lg shadow-primary/20 flex items-center justify-center gap-2 cursor-pointer active:scale-95"
          >
            <UserPlus size={16} />
            <span>Convidar Membro</span>
          </button>
        </div>

        {/* Cards de Métricas */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-6">
          <div className="p-4 rounded-xl bg-secondary/40 border border-border flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Users size={20} />
            </div>
            <div>
              <span className="text-xs text-zinc-400 font-medium">Total de Membros</span>
              <p className="text-2xl font-bold text-foreground">{totalCount}</p>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-secondary/40 border border-border flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <ShieldCheck size={20} />
            </div>
            <div>
              <span className="text-xs text-zinc-400 font-medium">Administradores</span>
              <p className="text-2xl font-bold text-foreground">{adminCount}</p>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-secondary/40 border border-border flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <Clock size={20} />
            </div>
            <div>
              <span className="text-xs text-zinc-400 font-medium">Convites Pendentes</span>
              <p className="text-2xl font-bold text-foreground">{pendingCount}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Lista de Membros */}
      <div className="glass rounded-2xl border border-border overflow-visible relative">
        <div className="p-5 border-b border-border bg-secondary/30 rounded-t-2xl flex items-center justify-between">
          <span className="text-sm font-semibold text-foreground">Equipe da Organização</span>
          <span className="text-xs text-zinc-400">{members.length} membros registrados</span>
        </div>

        <div className="divide-y divide-border/60">
          {members.map((member, index) => {
            const isNearBottom = index >= members.length - 2;
            const isLast = index === members.length - 1;
            return (
              <div 
                key={member.id} 
                className={`p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors relative ${isLast ? 'rounded-b-2xl' : ''}`}
                style={{ zIndex: activeDropdownId === member.id ? 40 : 1 }}
              >
                {/* Info Membro */}
                <div className="flex items-center gap-3.5">
                  <div className={`w-10 h-10 rounded-xl ${member.avatarColor} text-white font-bold flex items-center justify-center text-sm shadow-md`}>
                    {member.name.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex flex-col">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-foreground text-sm">{member.name}</span>
                      {member.role === 'owner' && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          Owner
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-zinc-400 flex items-center gap-1.5 mt-0.5">
                      <Mail size={12} className="text-zinc-500" />
                      {member.email}
                    </span>
                  </div>
                </div>

                {/* Papel e Status */}
                <div className="flex items-center gap-6">
                  <div className="flex flex-col items-start md:items-center">
                    <RoleBadge role={member.role} />
                    <span className="text-[11px] text-zinc-500 mt-1">{member.joinedAt}</span>
                  </div>

                  <div className="flex flex-col items-start md:items-center">
                    <StatusBadge status={member.status} />
                    <span className="text-[11px] text-zinc-500 mt-1">{member.lastActiveAt}</span>
                  </div>

                  {/* Dropdown de Ações */}
                  <MemberActionsMenu
                    member={member}
                    isNearBottom={isNearBottom}
                    isOpen={activeDropdownId === member.id}
                    onToggle={() => setActiveDropdownId(activeDropdownId === member.id ? null : member.id)}
                    onClose={() => setActiveDropdownId(null)}
                    onEditRole={() => setEditingMember(member)}
                    onResendInvite={() => handleResendInvite(member)}
                    onToggleStatus={() => handleToggleStatus(member)}
                    onRemove={() => setMemberToRemove(member)}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Modal Convidar Membro */}
      <AnimatePresence>
        {isInviteModalOpen && (
          <InviteMemberModal
            onClose={() => setIsInviteModalOpen(false)}
            onSuccess={(newMember) => {
              refreshMembers();
              setIsInviteModalOpen(false);
              onShowToast(`Convite enviado com sucesso para ${newMember.email}!`);
            }}
          />
        )}
      </AnimatePresence>

      {/* Modal Alterar Papel */}
      <AnimatePresence>
        {editingMember && (
          <EditRoleModal
            member={editingMember}
            onClose={() => setEditingMember(null)}
            onSuccess={() => {
              refreshMembers();
              setEditingMember(null);
              onShowToast('Papel do membro atualizado com sucesso.');
            }}
          />
        )}
      </AnimatePresence>

      {/* Modal Confirmar Remoção */}
      <AnimatePresence>
        {memberToRemove && (
          <RemoveMemberModal
            member={memberToRemove}
            onClose={() => setMemberToRemove(null)}
            onConfirm={handleConfirmRemove}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function RoleBadge({ role }: { role: MemberRole }) {
  switch (role) {
    case 'owner':
      return (
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
          Proprietário
        </span>
      );
    case 'admin':
      return (
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-primary/10 text-primary border border-primary/20">
          Administrador
        </span>
      );
    case 'operator':
      return (
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
          Operador
        </span>
      );
    case 'viewer':
      return (
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
          Visualizador
        </span>
      );
  }
}

function StatusBadge({ status }: { status: Member['status'] }) {
  switch (status) {
    case 'active':
      return (
        <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Ativo
        </span>
      );
    case 'invited':
      return (
        <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
          Pendente
        </span>
      );
    case 'suspended':
      return (
        <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
          Suspenso
        </span>
      );
  }
}

function InviteMemberModal({
  onClose,
  onSuccess
}: {
  onClose: () => void;
  onSuccess: (member: Member) => void;
}) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<MemberRole>('operator');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const result = inviteMember({ name, email, role });
    if (result.success && result.member) {
      onSuccess(result.member);
    } else {
      setError(result.error || 'Erro ao enviar convite.');
    }
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
        className="glass max-w-lg w-full rounded-2xl p-6 border border-border shadow-2xl relative overflow-hidden cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <UserPlus size={20} />
            </div>
            <div>
              <h4 className="text-xl font-bold text-foreground">Convidar Novo Membro</h4>
              <p className="text-xs text-zinc-400">Adicione uma pessoa à organização e conceda privilégios.</p>
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

        <form onSubmit={handleSubmit} className="flex flex-col gap-4 mt-5">
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-300">Nome Completo</label>
            <input 
              type="text" 
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              placeholder="Ex: Carlos Eduardo"
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground text-sm focus:outline-none focus:ring-2 transition-all"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-300">Endereço de E-mail Corporativo</label>
            <input 
              type="email" 
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              placeholder="carlos@empresa.com"
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground text-sm focus:outline-none focus:ring-2 transition-all"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-300">Papel de Autorização (Role)</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as MemberRole)}
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground text-sm focus:outline-none focus:ring-2 transition-all cursor-pointer"
            >
              <option value="admin">Administrador (Gestão de Chaves, Rotação e Membros)</option>
              <option value="operator">Operador (Ativação e Operação de Conexões)</option>
              <option value="viewer">Visualizador (Somente Leitura e Relatórios)</option>
            </select>
          </div>

          {/* Explicação do Papel */}
          <div className="p-3 bg-secondary/60 rounded-xl border border-border flex items-start gap-2.5 text-xs text-zinc-300 leading-relaxed">
            <HelpCircle size={16} className="text-primary flex-shrink-0 mt-0.5" />
            <span>{getRoleDescription(role)}</span>
          </div>

          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 text-xs flex items-center gap-2">
              <AlertTriangle size={15} />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-border mt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl text-sm font-medium text-zinc-400 hover:text-foreground hover:bg-white/5 border border-border transition-colors cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="bg-primary hover:bg-primary/90 text-primary-foreground px-5 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-lg shadow-primary/20 active:scale-95 cursor-pointer flex items-center gap-2"
            >
              <Send size={15} />
              <span>Enviar Convite</span>
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}

function EditRoleModal({
  member,
  onClose,
  onSuccess
}: {
  member: Member;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [selectedRole, setSelectedRole] = useState<MemberRole>(member.role);
  const [error, setError] = useState<string | null>(null);

  const handleSave = (e: FormEvent) => {
    e.preventDefault();
    const res = updateMemberRole(member.id, selectedRole);
    if (res.success) {
      onSuccess();
    } else {
      setError(res.error || 'Falha ao atualizar papel.');
    }
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
        className="glass max-w-md w-full rounded-2xl p-6 border border-border shadow-2xl relative overflow-hidden cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Shield size={20} />
            </div>
            <div>
              <h4 className="text-xl font-bold text-foreground">Alterar Papel de Acesso</h4>
              <p className="text-xs text-zinc-400">{member.name}</p>
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

        <form onSubmit={handleSave} className="flex flex-col gap-4 mt-5">
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-300">Selecione o Novo Papel</label>
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value as MemberRole)}
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground text-sm focus:outline-none focus:ring-2 transition-all cursor-pointer"
            >
              <option value="owner">Proprietário (Owner - Acesso Total)</option>
              <option value="admin">Administrador (Admin)</option>
              <option value="operator">Operador (Operator)</option>
              <option value="viewer">Visualizador (Viewer)</option>
            </select>
          </div>

          <div className="p-3 bg-secondary/60 rounded-xl border border-border text-xs text-zinc-300 leading-relaxed">
            {getRoleDescription(selectedRole)}
          </div>

          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 text-xs flex items-center gap-2">
              <AlertTriangle size={15} />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-border mt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl text-sm font-medium text-zinc-400 hover:text-foreground hover:bg-white/5 border border-border transition-colors cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="bg-primary hover:bg-primary/90 text-primary-foreground px-5 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-lg shadow-primary/20 active:scale-95 cursor-pointer"
            >
              Salvar Alteração
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}

function RemoveMemberModal({
  member,
  onClose,
  onConfirm
}: {
  member: Member;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md cursor-pointer"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.9, y: 20 }}
        className="glass max-w-md w-full rounded-2xl p-6 border border-rose-500/30 shadow-2xl relative overflow-hidden cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center flex-shrink-0 text-rose-400">
            <AlertTriangle size={24} />
          </div>
          <div className="flex-1">
            <h4 className="text-xl font-bold text-foreground">Remover Membro da Organização?</h4>
            <p className="text-zinc-400 text-sm mt-2 leading-relaxed">
              O acesso de <strong>{member.name}</strong> ({member.email}) será revogado imediatamente de todas as conexões Zatten e ferramentas de integração.
            </p>
          </div>
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
            className="bg-rose-500 hover:bg-rose-600 text-white px-5 py-2.5 rounded-xl text-sm font-medium transition-colors shadow-lg shadow-rose-500/20 cursor-pointer"
          >
            Sim, Remover Membro
          </button>
        </div>
      </motion.div>
    </div>
  );
}

function MemberActionsMenu({
  member,
  isNearBottom,
  isOpen,
  onToggle,
  onClose,
  onEditRole,
  onResendInvite,
  onToggleStatus,
  onRemove
}: {
  member: Member;
  isNearBottom: boolean;
  isOpen: boolean;
  onToggle: () => void;
  onClose: () => void;
  onEditRole: () => void;
  onResendInvite: () => void;
  onToggleStatus: () => void;
  onRemove: () => void;
}) {
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    function handlePointerDown(e: MouseEvent | TouchEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    }
    document.addEventListener('pointerdown', handlePointerDown);
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, [isOpen, onClose]);

  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        onClick={onToggle}
        className="p-2 rounded-lg text-zinc-400 hover:text-foreground hover:bg-white/5 transition-colors cursor-pointer"
        title="Ações do membro"
      >
        <MoreVertical size={16} />
      </button>

      {isOpen && (
        <div 
          className={`absolute right-0 ${
            isNearBottom ? 'bottom-full mb-1.5' : 'top-full mt-1.5'
          } w-48 bg-secondary/95 backdrop-blur-md border border-border rounded-xl shadow-2xl p-1.5 z-50 flex flex-col gap-1 text-xs`}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            type="button"
            onClick={() => {
              onEditRole();
              onClose();
            }}
            className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-white/5 text-zinc-200 transition-colors w-full text-left cursor-pointer"
          >
            <Edit3 size={14} className="text-primary" />
            <span>Alterar Papel</span>
          </button>

          {member.status === 'invited' && (
            <button
              type="button"
              onClick={() => {
                onResendInvite();
                onClose();
              }}
              className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-white/5 text-zinc-200 transition-colors w-full text-left cursor-pointer"
            >
              <Send size={14} className="text-blue-400" />
              <span>Reenviar Convite</span>
            </button>
          )}

          {member.role !== 'owner' && (
            <button
              type="button"
              onClick={() => {
                onToggleStatus();
                onClose();
              }}
              className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-white/5 text-zinc-200 transition-colors w-full text-left cursor-pointer"
            >
              {member.status === 'suspended' ? (
                <>
                  <UserCheck size={14} className="text-emerald-400" />
                  <span>Reativar Acesso</span>
                </>
              ) : (
                <>
                  <UserX size={14} className="text-amber-400" />
                  <span>Suspender Acesso</span>
                </>
              )}
            </button>
          )}

          {member.role !== 'owner' && (
            <button
              type="button"
              onClick={() => {
                onRemove();
                onClose();
              }}
              className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-rose-500/10 text-rose-400 transition-colors w-full text-left cursor-pointer border-t border-border/50 pt-2"
            >
              <Trash2 size={14} />
              <span>Remover da Equipe</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
}
