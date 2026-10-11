import { z } from 'zod';
import { addAuditLog } from './audit';

export type MemberRole = 'owner' | 'admin' | 'operator' | 'viewer';
export type MemberStatus = 'active' | 'invited' | 'suspended';

export interface Member {
  id: string;
  name: string;
  email: string;
  role: MemberRole;
  status: MemberStatus;
  joinedAt: string;
  lastActiveAt: string;
  avatarColor: string;
}

export const inviteMemberSchema = z.object({
  name: z.string().min(2, { message: 'O nome deve ter pelo menos 2 caracteres.' }).max(60),
  email: z.string().email({ message: 'Informe um endereço de e-mail válido.' }),
  role: z.enum(['owner', 'admin', 'operator', 'viewer'], {
    message: 'Selecione um papel válido para o membro.'
  })
});

export type InviteMemberInput = z.infer<typeof inviteMemberSchema>;

const STORAGE_KEY = 'zatten_members_list_v2';

const INITIAL_MEMBERS: Member[] = [
  {
    id: 'mem_01',
    name: 'Administrador (Dono)',
    email: 'contato@firstsys.com.br',
    role: 'owner',
    status: 'active',
    joinedAt: new Date().toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' }),
    lastActiveAt: 'Agora mesmo',
    avatarColor: 'bg-emerald-500'
  }
];

const AVATAR_COLORS = [
  'bg-blue-500',
  'bg-emerald-500',
  'bg-purple-500',
  'bg-rose-500',
  'bg-amber-500',
  'bg-cyan-500',
  'bg-indigo-500'
];

export function getMembers(): Member[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_MEMBERS));
      return INITIAL_MEMBERS;
    }
    return JSON.parse(raw);
  } catch (err) {
    console.error('Erro ao ler membros:', err);
    return INITIAL_MEMBERS;
  }
}

function saveMembers(members: Member[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(members));
  } catch (err) {
    console.error('Erro ao salvar membros:', err);
  }
}

export function inviteMember(data: InviteMemberInput): { success: boolean; member?: Member; error?: string } {
  const validation = inviteMemberSchema.safeParse(data);
  if (!validation.success) {
    return { 
      success: false, 
      error: validation.error.issues[0]?.message || 'Dados de convite inválidos.' 
    };
  }

  const current = getMembers();
  if (current.some(m => m.email.toLowerCase() === data.email.toLowerCase())) {
    return {
      success: false,
      error: 'Já existe um membro ou convite registrado com este endereço de e-mail.'
    };
  }

  const color = AVATAR_COLORS[Math.floor(Math.random() * AVATAR_COLORS.length)];
  const newMember: Member = {
    id: `mem_${Date.now().toString(36)}`,
    name: data.name.trim(),
    email: data.email.trim().toLowerCase(),
    role: data.role,
    status: 'invited',
    joinedAt: new Date().toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' }),
    lastActiveAt: 'Pendente de aceite',
    avatarColor: color
  };

  const updated = [...current, newMember];
  saveMembers(updated);

  addAuditLog({
    action: 'member.invited',
    category: 'members',
    severity: 'info',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: `Novo convite de membro enviado para ${newMember.email} com papel de ${getRoleLabel(newMember.role)}`,
    details: {
      memberId: newMember.id,
      email: newMember.email,
      role: newMember.role
    }
  });

  return { success: true, member: newMember };
}

export function updateMemberRole(id: string, newRole: MemberRole): { success: boolean; error?: string } {
  const current = getMembers();
  const index = current.findIndex(m => m.id === id);
  if (index === -1) {
    return { success: false, error: 'Membro não encontrado.' };
  }

  const member = current[index];
  // Impede remover o último Owner
  if (member.role === 'owner' && newRole !== 'owner') {
    const ownerCount = current.filter(m => m.role === 'owner').length;
    if (ownerCount <= 1) {
      return { success: false, error: 'A organização deve manter pelo menos um Proprietário (Owner) ativo.' };
    }
  }

  const previousRole = member.role;
  current[index] = { ...member, role: newRole };
  saveMembers(current);

  addAuditLog({
    action: 'member.role_updated',
    category: 'members',
    severity: 'info',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: `Papel de ${member.name} (${member.email}) alterado de ${getRoleLabel(previousRole)} para ${getRoleLabel(newRole)}`,
    details: {
      memberId: id,
      previousRole,
      newRole
    }
  });

  return { success: true };
}

export function toggleMemberStatus(id: string): { success: boolean; newStatus?: MemberStatus; error?: string } {
  const current = getMembers();
  const index = current.findIndex(m => m.id === id);
  if (index === -1) {
    return { success: false, error: 'Membro não encontrado.' };
  }

  const member = current[index];
  if (member.role === 'owner') {
    return { success: false, error: 'Não é permitido suspender o Proprietário da conta.' };
  }

  const nextStatus: MemberStatus = member.status === 'suspended' ? 'active' : 'suspended';
  current[index] = { ...member, status: nextStatus };
  saveMembers(current);

  addAuditLog({
    action: 'member.status_toggled',
    category: 'members',
    severity: nextStatus === 'suspended' ? 'warning' : 'info',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: `Acesso do membro ${member.email} ${nextStatus === 'suspended' ? 'suspenso temporariamente' : 'reativado'}`,
    details: {
      memberId: id,
      newStatus: nextStatus
    }
  });

  return { success: true, newStatus: nextStatus };
}

export function resendInvite(id: string): { success: boolean; error?: string } {
  const current = getMembers();
  const member = current.find(m => m.id === id);
  if (!member) {
    return { success: false, error: 'Membro não encontrado.' };
  }

  addAuditLog({
    action: 'member.invite_resent',
    category: 'members',
    severity: 'info',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: `Convite de acesso reenviado com sucesso para ${member.email}`,
    details: {
      memberId: id,
      email: member.email
    }
  });

  return { success: true };
}

export function removeMember(id: string): { success: boolean; error?: string } {
  const current = getMembers();
  const member = current.find(m => m.id === id);
  if (!member) {
    return { success: false, error: 'Membro não encontrado.' };
  }

  if (member.role === 'owner') {
    return { success: false, error: 'O Proprietário da organização não pode ser removido.' };
  }

  const updated = current.filter(m => m.id !== id);
  saveMembers(updated);

  addAuditLog({
    action: 'member.removed',
    category: 'members',
    severity: 'warning',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: `Membro ${member.name} (${member.email}) removido da organização`,
    details: {
      memberId: id,
      email: member.email,
      role: member.role
    }
  });

  return { success: true };
}

export function getRoleLabel(role: MemberRole): string {
  switch (role) {
    case 'owner': return 'Proprietário';
    case 'admin': return 'Administrador';
    case 'operator': return 'Operador';
    case 'viewer': return 'Visualizador';
  }
}

export function getRoleDescription(role: MemberRole): string {
  switch (role) {
    case 'owner': return 'Controle total da organização, faturamento, rotação de chaves mestras e membros.';
    case 'admin': return 'Pode cadastrar conexões Zatten, rotacionar chaves, gerenciar operadores e visualizar logs.';
    case 'operator': return 'Pode ativar/desativar conexões autorizadas e operar integrações operacionais.';
    case 'viewer': return 'Apenas visualização de relatórios, status de conexões e histórico de auditoria.';
  }
}
