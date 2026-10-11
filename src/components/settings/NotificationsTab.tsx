import { useState, type FormEvent } from 'react';
import { 
  Mail, 
  Webhook, 
  Send, 
  Radio, 
  Check, 
  Copy,
  MessageSquareCode
} from 'lucide-react';
import { 
  type NotificationSettings, 
  getNotificationSettings, 
  saveNotificationSettings, 
  sendTestNotification 
} from '../../lib/notifications';

interface NotificationsTabProps {
  onShowToast: (msg: string) => void;
}

export default function NotificationsTab({ onShowToast }: NotificationsTabProps) {
  const [settings, setSettings] = useState<NotificationSettings>(() => getNotificationSettings());
  const [isTestingChannel, setIsTestingChannel] = useState<'email' | 'webhook' | 'slack' | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  const handleToggle = (key: keyof NotificationSettings) => {
    setSettings(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const handleCopySecret = () => {
    if (!settings.webhookSecret) return;
    navigator.clipboard.writeText(settings.webhookSecret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  const handleTest = async (type: 'email' | 'webhook' | 'slack') => {
    setIsTestingChannel(type);
    const result = await sendTestNotification(type);
    setIsTestingChannel(null);
    if (result.success) {
      setSettings(getNotificationSettings());
      onShowToast(result.message);
    } else {
      onShowToast(`Erro: ${result.message}`);
    }
  };

  const handleSaveAll = (e: FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    const result = saveNotificationSettings(settings);
    setIsSaving(false);
    if (result.success) {
      onShowToast('Preferências de notificação salvas com sucesso.');
    } else {
      onShowToast(result.error || 'Erro ao salvar preferências.');
    }
  };

  return (
    <form onSubmit={handleSaveAll} className="flex flex-col gap-6">
      {/* Cabeçalho */}
      <div className="glass rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h3 className="text-xl font-bold text-foreground">Canais de Notificação</h3>
            <p className="text-zinc-400 text-sm mt-1">
              Receba alertas imediatos sobre incidentes de segurança, rotações de chave e alterações administrativas.
            </p>
          </div>
          <button
            type="submit"
            disabled={isSaving}
            className="bg-primary hover:bg-primary/90 text-primary-foreground px-5 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-lg shadow-primary/20 cursor-pointer active:scale-95 disabled:opacity-50"
          >
            {isSaving ? 'Gravando...' : 'Salvar Alterações'}
          </button>
        </div>
      </div>

      {/* Canais Principais */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Canal 1: E-mail de Segurança */}
        <div className="glass rounded-2xl p-6 flex flex-col justify-between border border-border">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                  <Mail size={20} />
                </div>
                <div>
                  <h4 className="text-base font-semibold text-foreground">E-mail Administrativo</h4>
                  <p className="text-xs text-zinc-400">Notificações diretas para a equipe de segurança</p>
                </div>
              </div>
              <ToggleSwitch 
                checked={settings.emailEnabled} 
                onChange={() => handleToggle('emailEnabled')} 
              />
            </div>

            <div className="flex flex-col gap-2 mt-4">
              <label className="text-xs font-semibold text-zinc-300">Destinatário Principal</label>
              <input
                type="email"
                value={settings.adminEmail}
                onChange={(e) => setSettings({ ...settings, adminEmail: e.target.value })}
                placeholder="seguranca@suaempresa.com"
                className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground text-sm focus:outline-none focus:ring-2 transition-all"
              />
              <span className="text-[11px] text-zinc-500">
                Endereço que receberá resumos de auditoria e avisos de revogação.
              </span>
            </div>
          </div>

          <div className="pt-4 border-t border-border mt-5 flex justify-end">
            <button
              type="button"
              disabled={!settings.emailEnabled || isTestingChannel === 'email'}
              onClick={() => handleTest('email')}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold text-zinc-300 hover:text-white bg-white/5 hover:bg-white/10 border border-border transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Send size={13} className={isTestingChannel === 'email' ? 'animate-pulse text-primary' : ''} />
              <span>{isTestingChannel === 'email' ? 'Disparando...' : 'Testar Envio'}</span>
            </button>
          </div>
        </div>

        {/* Canal 2: Slack / Discord */}
        <div className="glass rounded-2xl p-6 flex flex-col justify-between border border-border">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                  <MessageSquareCode size={20} />
                </div>
                <div>
                  <h4 className="text-base font-semibold text-foreground">Slack / Discord (Incoming Webhook)</h4>
                  <p className="text-xs text-zinc-400">Mensagens em canal dedicado de incidentes</p>
                </div>
              </div>
              <ToggleSwitch 
                checked={settings.slackEnabled} 
                onChange={() => handleToggle('slackEnabled')} 
              />
            </div>

            <div className="flex flex-col gap-2 mt-4">
              <label className="text-xs font-semibold text-zinc-300">Webhook URL do Canal</label>
              <input
                type="url"
                value={settings.slackWebhookUrl}
                onChange={(e) => setSettings({ ...settings, slackWebhookUrl: e.target.value })}
                placeholder="https://hooks.slack.com/services/T00/B00/XXXX"
                className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground text-sm font-mono focus:outline-none focus:ring-2 transition-all"
              />
              <span className="text-[11px] text-zinc-500">
                Compatível com payloads de Webhook padrão do Slack e Discord.
              </span>
            </div>
          </div>

          <div className="pt-4 border-t border-border mt-5 flex justify-end">
            <button
              type="button"
              disabled={!settings.slackEnabled || isTestingChannel === 'slack'}
              onClick={() => handleTest('slack')}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold text-zinc-300 hover:text-white bg-white/5 hover:bg-white/10 border border-border transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Send size={13} className={isTestingChannel === 'slack' ? 'animate-pulse text-purple-400' : ''} />
              <span>{isTestingChannel === 'slack' ? 'Testando...' : 'Testar Mensagem'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Canal 3: Webhook HTTP Customizado (SIEM / Event Driven) */}
      <div className="glass rounded-2xl p-6 border border-border">
        <div className="flex items-center justify-between pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <Webhook size={20} />
            </div>
            <div>
              <h4 className="text-base font-semibold text-foreground">Webhook HTTP com Assinatura HMAC (SIEM)</h4>
              <p className="text-xs text-zinc-400">Disparo assíncrono de eventos com cabeçalho de integridade X-Zatten-Signature</p>
            </div>
          </div>
          <ToggleSwitch 
            checked={settings.webhookEnabled} 
            onChange={() => handleToggle('webhookEnabled')} 
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-300">Endpoint HTTPS do Webhook</label>
            <input
              type="url"
              value={settings.webhookUrl}
              onChange={(e) => setSettings({ ...settings, webhookUrl: e.target.value })}
              placeholder="https://siem.internal.empresa.com/events"
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground text-sm font-mono focus:outline-none focus:ring-2 transition-all"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-300">Secret Key (HMAC-SHA256)</label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                readOnly
                value={settings.webhookSecret}
                className="bg-secondary border border-border rounded-xl px-4 py-2.5 text-foreground text-sm font-mono flex-1 select-all"
              />
              <button
                type="button"
                onClick={handleCopySecret}
                className="p-2.5 rounded-xl border border-border bg-white/5 hover:bg-white/10 text-zinc-300 hover:text-white transition-colors cursor-pointer"
                title="Copiar Chave Secreta"
              >
                {copiedSecret ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} />}
              </button>
            </div>
          </div>
        </div>

        <div className="mt-4 p-3 bg-secondary/40 rounded-xl border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <span className="text-zinc-400">
            Último status de envio: <strong className="text-foreground">{settings.lastWebhookPingAt || 'Nenhum disparo recente'}</strong>
          </span>
          <button
            type="button"
            disabled={!settings.webhookEnabled || isTestingChannel === 'webhook'}
            onClick={() => handleTest('webhook')}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-primary bg-primary/10 hover:bg-primary/20 border border-primary/30 transition-colors flex items-center gap-2 cursor-pointer self-start sm:self-auto disabled:opacity-40"
          >
            <Radio size={14} className={isTestingChannel === 'webhook' ? 'animate-spin' : ''} />
            <span>{isTestingChannel === 'webhook' ? 'Disparando Ping...' : 'Disparar Webhook de Teste'}</span>
          </button>
        </div>
      </div>

      {/* Matriz de Eventos de Segurança */}
      <div className="glass rounded-2xl p-6 border border-border">
        <h4 className="text-base font-bold text-foreground mb-1">Matriz de Gatilhos de Notificação</h4>
        <p className="text-xs text-zinc-400 mb-5">
          Selecione quais eventos devem disparar notificações automáticas nos canais ativados acima:
        </p>

        <div className="flex flex-col divide-y divide-border/60">
          <EventRow
            title="Rotação de Chave Mestra (OpenBao Transit)"
            description="Dispara alerta quando uma nova versão da chave mestra KMS for gerada com sucesso."
            checked={settings.eventMasterKeyRotation}
            onToggle={() => handleToggle('eventMasterKeyRotation')}
          />
          <EventRow
            title="Conexão Zatten Revogada ou Inoperante"
            description="Notifica administradores quando uma conexão tiver status alterado para 'revoked' ou falhar na validação."
            checked={settings.eventConnectionRevoked}
            onToggle={() => handleToggle('eventConnectionRevoked')}
          />
          <EventRow
            title="Requisições Bloqueadas por CORS ou IP Não Autorizado"
            description="Alerta sobre tentativas externas de consumo de API a partir de origens não autorizadas."
            checked={settings.eventCorsBlocked}
            onToggle={() => handleToggle('eventCorsBlocked')}
          />
          <EventRow
            title="Falhas Repetidas de Autenticação / 2FA (MFA)"
            description="Avisa em caso de códigos TOTP incorretos ou suspeita de força bruta no painel."
            checked={settings.eventMfaFailed}
            onToggle={() => handleToggle('eventMfaFailed')}
          />
          <EventRow
            title="Chamadas de Escrita Sensíveis via MCP (ChatGPT)"
            description="Registra e alerta quando o agente MCP executar comandos de escrita ou alteração de estado."
            checked={settings.eventMcpWriteAction}
            onToggle={() => handleToggle('eventMcpWriteAction')}
          />
        </div>
      </div>
    </form>
  );
}

function EventRow({
  title,
  description,
  checked,
  onToggle
}: {
  title: string;
  description: string;
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="py-3.5 flex items-center justify-between gap-4">
      <div className="flex flex-col">
        <span className="text-sm font-medium text-foreground">{title}</span>
        <span className="text-xs text-zinc-400 mt-0.5">{description}</span>
      </div>
      <ToggleSwitch checked={checked} onChange={onToggle} />
    </div>
  );
}

function ToggleSwitch({ checked, onChange }: { checked: boolean; onChange: () => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={onChange}
      className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
        checked ? 'bg-[#34C759]' : 'bg-zinc-700'
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
          checked ? 'translate-x-5' : 'translate-x-0'
        }`}
      />
    </button>
  );
}
