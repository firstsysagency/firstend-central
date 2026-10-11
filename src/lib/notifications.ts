import { z } from 'zod';
import { addAuditLog } from './audit';

export interface NotificationSettings {
  // Canal 1: E-mail Administrativo
  emailEnabled: boolean;
  adminEmail: string;

  // Canal 2: Webhook HTTP
  webhookEnabled: boolean;
  webhookUrl: string;
  webhookSecret: string;
  lastWebhookPingAt: string | null;

  // Canal 3: Slack / Discord
  slackEnabled: boolean;
  slackWebhookUrl: string;

  // Matriz de Eventos de Segurança
  eventMasterKeyRotation: boolean;
  eventConnectionRevoked: boolean;
  eventCorsBlocked: boolean;
  eventMfaFailed: boolean;
  eventMcpWriteAction: boolean;
}

export const notificationSettingsSchema = z.object({
  emailEnabled: z.boolean(),
  adminEmail: z.string().email({ message: 'E-mail administrativo de alerta inválido.' }).or(z.literal('')),
  webhookEnabled: z.boolean(),
  webhookUrl: z.string().url({ message: 'URL do webhook deve ser válida.' }).or(z.literal('')),
  webhookSecret: z.string().max(128),
  slackEnabled: z.boolean(),
  slackWebhookUrl: z.string().url({ message: 'URL do Slack/Discord deve ser válida.' }).or(z.literal('')),
  eventMasterKeyRotation: z.boolean(),
  eventConnectionRevoked: z.boolean(),
  eventCorsBlocked: z.boolean(),
  eventMfaFailed: z.boolean(),
  eventMcpWriteAction: z.boolean()
});

const STORAGE_KEY = 'zatten_notifications_settings_v1';

export const DEFAULT_NOTIFICATIONS: NotificationSettings = {
  emailEnabled: true,
  adminEmail: 'seguranca@zatten.com',
  webhookEnabled: true,
  webhookUrl: 'https://webhook.internal.firstsys.com.br/security-events',
  webhookSecret: 'sec_whk_98b3c10f84a1e93',
  lastWebhookPingAt: 'Hoje às 14:15 (200 OK)',
  slackEnabled: false,
  slackWebhookUrl: '',
  eventMasterKeyRotation: true,
  eventConnectionRevoked: true,
  eventCorsBlocked: true,
  eventMfaFailed: true,
  eventMcpWriteAction: true
};

export function getNotificationSettings(): NotificationSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULT_NOTIFICATIONS));
      return DEFAULT_NOTIFICATIONS;
    }
    return JSON.parse(raw);
  } catch (err) {
    console.error('Erro ao ler configurações de notificação:', err);
    return DEFAULT_NOTIFICATIONS;
  }
}

export function saveNotificationSettings(settings: NotificationSettings): { success: boolean; error?: string } {
  const validation = notificationSettingsSchema.safeParse(settings);
  if (!validation.success) {
    return { 
      success: false, 
      error: validation.error.issues[0]?.message || 'Configurações de notificação inválidas.' 
    };
  }

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
    addAuditLog({
      action: 'notifications.settings_updated',
      category: 'notifications',
      severity: 'info',
      actor: 'admin@zatten.com',
      ipAddress: '192.168.1.104',
      description: 'Configurações de canais de notificação e gatilhos de segurança atualizadas',
      details: {
        emailEnabled: settings.emailEnabled,
        webhookEnabled: settings.webhookEnabled,
        slackEnabled: settings.slackEnabled
      }
    });
    return { success: true };
  } catch (err) {
    console.error('Erro ao salvar notificações:', err);
    return { success: false, error: 'Falha ao gravar no armazenamento local.' };
  }
}

export async function sendTestNotification(type: 'email' | 'webhook' | 'slack'): Promise<{
  success: boolean;
  message: string;
  timestamp: string;
}> {
  const current = getNotificationSettings();
  const now = new Date();
  const timeStr = 'Hoje às ' + now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });

  // Simulação controlada de handshake com timeout
  await new Promise(r => setTimeout(r, 900));

  let message = '';
  if (type === 'webhook') {
    if (!current.webhookUrl) {
      return { success: false, message: 'URL do Webhook não configurada.', timestamp: timeStr };
    }
    current.lastWebhookPingAt = `${timeStr} (200 OK)`;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(current));
    message = `Evento de teste disparado com sucesso para ${current.webhookUrl} com assinatura HMAC-SHA256 (HTTP 200).`;
  } else if (type === 'email') {
    message = `Notificação de teste de segurança enviada para a caixa de correio ${current.adminEmail || 'admin@zatten.com'}.`;
  } else {
    message = `Mensagem de teste formatada e despachada para o canal Slack/Discord.`;
  }

  addAuditLog({
    action: 'notifications.test_dispatched',
    category: 'notifications',
    severity: 'info',
    actor: 'admin@zatten.com',
    ipAddress: '192.168.1.104',
    description: `Disparo de teste de notificação executado no canal: ${type.toUpperCase()}`,
    details: {
      channel: type,
      destination: type === 'webhook' ? current.webhookUrl : current.adminEmail
    }
  });

  return {
    success: true,
    message,
    timestamp: timeStr
  };
}
