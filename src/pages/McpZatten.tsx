import { useState, useMemo, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bot, Shield, Check, X, ShieldAlert, Search, Save, CheckCircle2, RotateCcw, Loader2, Copy, ExternalLink, Sparkles, ChevronDown, ChevronUp } from 'lucide-react';
import { logAuditEvent } from '../lib/audit';

interface McpPermission {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  danger?: boolean;
}

const STORAGE_KEY = 'zatten_mcp_permissions';

const ALL_PERMISSIONS: McpPermission[] = [
  { id: 'zatten_kanban_get', name: 'Buscar Colunas (zatten_kanban_get)', description: 'Busca informações de todas as colunas do Kanban.', enabled: true },
  { id: 'zatten_leads_leadnumber_assignee_patch', name: 'Atualizar Responsável (zatten_leads_leadnumber_assignee_patch)', description: 'Atualiza o responsável (usuário e departamento) de um lead.', enabled: true, danger: true },
  { id: 'zatten_leads_leadnumber_get', name: 'Obter Lead (zatten_leads_leadnumber_get)', description: 'Obtém informações de um lead específico.', enabled: true },
  { id: 'zatten_leads_leadnumber_kanban_patch', name: 'Mover Lead no Kanban (zatten_leads_leadnumber_kanban_patch)', description: 'Move um lead entre colunas no Kanban.', enabled: true, danger: true },
  { id: 'zatten_leads_leadnumber_notes_patch', name: 'Atualizar Anotação (zatten_leads_leadnumber_notes_patch)', description: 'Atualiza ou adiciona anotações em um lead.', enabled: true, danger: true },
  { id: 'zatten_leads_leadnumber_properties_patch', name: 'Atualizar Propriedade (zatten_leads_leadnumber_properties_patch)', description: 'Atualiza propriedades customizadas de um lead.', enabled: true, danger: true },
  { id: 'zatten_leads_leadnumber_tag_delete', name: 'Remover Tag (zatten_leads_leadnumber_tag_delete)', description: 'Remove uma tag associada a um lead.', enabled: true, danger: true },
  { id: 'zatten_leads_leadnumber_tag_post', name: 'Adicionar Tag (zatten_leads_leadnumber_tag_post)', description: 'Adiciona uma tag a um lead.', enabled: true, danger: true },
  { id: 'zatten_leads_leadnumber_threads_get', name: 'Listar Threads do Lead (zatten_leads_leadnumber_threads_get)', description: 'Lista todas as threads vinculadas a um lead.', enabled: true },
  { id: 'zatten_leads_leadnumber_toggle_attendant_response_post', name: 'Alternar IA (zatten_leads_leadnumber_toggle_attendant_response_post)', description: 'Ativa ou desativa a resposta automática do atendente de IA para um lead.', enabled: true, danger: true },
  { id: 'zatten_users_get', name: 'Listar Usuários e Atendentes (zatten_users_get)', description: 'Consulta atendentes, usuários e responsáveis cadastrados no CRM Zatten.', enabled: true },
  { id: 'zatten_templates_get', name: 'Listar Templates HSM (zatten_templates_get)', description: 'Consulta os templates HSM aprovados pela Meta WhatsApp Business API.', enabled: true },
  { id: 'zatten_attendants_list', name: 'Listar Equipe (zatten_attendants_list)', description: 'Lista membros da equipe cadastrados para atribuição de responsável.', enabled: true },
  { id: 'zatten_templates_list', name: 'Templates HSM Legados (zatten_templates_list)', description: 'Consulta lista de templates cadastrados.', enabled: true },
  { id: 'zatten_list_connections', name: 'Listar Conexões (zatten_list_connections)', description: 'Lista as conexões Zatten ativas na organização.', enabled: true },
  { id: 'zatten_messages_audio_post', name: 'Enviar Áudio (zatten_messages_audio_post)', description: 'Envia uma mensagem de áudio.', enabled: true },
  { id: 'zatten_messages_file_post', name: 'Enviar Arquivo (zatten_messages_file_post)', description: 'Envia uma mensagem de arquivo (documentos).', enabled: true },
  { id: 'zatten_messages_history_get', name: 'Histórico de Mensagens (zatten_messages_history_get)', description: 'Busca o histórico de mensagens de um lead (com suporte a formatação LLM).', enabled: true },
  { id: 'zatten_messages_image_post', name: 'Enviar Imagem (zatten_messages_image_post)', description: 'Envia uma mensagem de imagem.', enabled: true },
  { id: 'zatten_messages_template_post', name: 'Enviar Template (zatten_messages_template_post)', description: 'Envia uma mensagem de template HSM.', enabled: true },
  { id: 'zatten_messages_text_post', name: 'Enviar Texto (zatten_messages_text_post)', description: 'Envia uma mensagem de texto simples.', enabled: true },
  { id: 'zatten_messages_video_post', name: 'Enviar Vídeo (zatten_messages_video_post)', description: 'Envia uma mensagem de vídeo.', enabled: true },
  { id: 'zatten_send_message', name: 'Enviar Mensagem Segura (zatten_send_message)', description: 'Envia mensagem a um contato via API Zatten. EXIGE CONFIRMAÇÃO DO USUÁRIO.', enabled: true },
  { id: 'zatten_tags_get', name: 'Buscar Tags (zatten_tags_get)', description: 'Busca informações de todas as tags disponíveis.', enabled: true }
].sort((a, b) => a.name.localeCompare(b.name));

function getInitialPermissions(): McpPermission[] {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return ALL_PERMISSIONS.map(def => {
          const found = parsed.find((p: McpPermission) => p.id === def.id);
          return found ? { ...def, enabled: found.enabled } : def;
        });
      }
    }
  } catch (e) {
    console.error('Erro ao recuperar permissões salvas do MCP', e);
  }
  return ALL_PERMISSIONS;
}

export default function McpZatten() {
  const [permissions, setPermissions] = useState<McpPermission[]>(getInitialPermissions);
  const [savedPermissions, setSavedPermissions] = useState<McpPermission[]>(getInitialPermissions);
  const [searchTerm, setSearchTerm] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [copiedOpenApi, setCopiedOpenApi] = useState(false);
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [showChatGptInstructions, setShowChatGptInstructions] = useState(false);

  // Sincroniza com o servidor ao inicializar com preservação de estado
  useEffect(() => {
    async function loadServerPermissions() {
      try {
        const res = await fetch('/api/mcp/permissions');
        if (res.ok) {
          const data = await res.json();
          const serverList: McpPermission[] = Array.isArray(data.permissions) ? data.permissions : [];
          
          let localList: McpPermission[] = [];
          try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) localList = JSON.parse(raw);
          } catch {}

          const merged = ALL_PERMISSIONS.map(def => {
            const foundServer = serverList.find(p => p.id === def.id);
            const foundLocal = localList.find(p => p.id === def.id);
            // Se o usuário já ativou localmente ou no servidor, prioriza manter ativado
            let isEnabled = def.enabled;
            if (foundLocal !== undefined) {
              isEnabled = foundLocal.enabled;
            } else if (foundServer !== undefined) {
              isEnabled = foundServer.enabled;
            }
            return { ...def, enabled: isEnabled };
          });

          setPermissions(merged);
          setSavedPermissions(merged);
          localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
        }
      } catch {
        // Mantém os dados locais já carregados sem sobrescrever
      }
    }
    loadServerPermissions();
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 3500);
  };

  const togglePermission = (id: string) => {
    setPermissions(prev => {
      const updated = prev.map(p => 
        p.id === id ? { ...p, enabled: !p.enabled } : p
      );
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch {}
      return updated;
    });
  };

  const handleEnableAll = () => {
    const updated = permissions.map(p => ({ ...p, enabled: true }));
    setPermissions(updated);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch {}
    showToast('Todas as ações foram habilitadas! Clique em Salvar para fixar no servidor.');
  };

  const handleDisableAll = () => {
    const updated = permissions.map(p => ({ ...p, enabled: false }));
    setPermissions(updated);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch {}
    showToast('Todas as ações foram desabilitadas.');
  };

  const hasUnsavedChanges = useMemo(() => {
    return JSON.stringify(permissions) !== JSON.stringify(savedPermissions);
  }, [permissions, savedPermissions]);

  const enabledCount = useMemo(() => {
    return permissions.filter(p => p.enabled).length;
  }, [permissions]);

  const handleSaveChanges = async () => {
    setIsSaving(true);
    try {
      // 1. Persistência local no navegador
      localStorage.setItem(STORAGE_KEY, JSON.stringify(permissions));

      // 2. Persistência no backend (Cofre Central)
      try {
        await fetch('/api/mcp/permissions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ permissions })
        });
      } catch (err) {
        console.warn('Backend offline ou inacessível, permissões salvas localmente.', err);
      }

      // 3. Auditoria militar contínua
      logAuditEvent({
        action: 'mcp.permissions_updated',
        category: 'mcp',
        severity: 'info',
        actor: 'Administrador',
        ipAddress: '127.0.0.1',
        description: 'Configurações de ações da IA via MCP Zatten salvas com sucesso.',
        details: {
          totalActions: permissions.length,
          activeActions: permissions.filter(p => p.enabled).map(p => p.id)
        }
      });

      setSavedPermissions(permissions);
      setSaveSuccess(true);
      showToast('Alterações salvas com sucesso!');
      setTimeout(() => setSaveSuccess(false), 2500);
    } catch (error) {
      console.error('Erro ao salvar permissões do MCP', error);
      showToast('Erro ao salvar alterações.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleDiscardChanges = () => {
    setPermissions(savedPermissions);
    showToast('Alterações descartadas.');
  };

  const handleCopyOpenApi = async () => {
    try {
      const res = await fetch('/openapi.json');
      if (res.ok) {
        const json = await res.json();
        await navigator.clipboard.writeText(JSON.stringify(json, null, 2));
        setCopiedOpenApi(true);
        showToast('Schema OpenAPI copiado para a área de transferência!');
        setTimeout(() => setCopiedOpenApi(false), 3000);
      } else {
        const schemaUrl = `${window.location.origin}/openapi.json`;
        await navigator.clipboard.writeText(schemaUrl);
        setCopiedOpenApi(true);
        showToast('URL do Schema OpenAPI copiada!');
        setTimeout(() => setCopiedOpenApi(false), 3000);
      }
    } catch {
      const schemaUrl = `${window.location.origin}/openapi.json`;
      await navigator.clipboard.writeText(schemaUrl);
      setCopiedOpenApi(true);
      showToast('URL do Schema copiada!');
      setTimeout(() => setCopiedOpenApi(false), 3000);
    }
  };

  const handleCopyConfig = async () => {
    const origin = window.location.origin;
    const configText = `Client ID: chatgpt-firstsys-mcp
Client Secret: firstsys_chatgpt_mcp_secret_2026
Authorization URL: ${origin}/oauth/authorize
Token URL: ${origin}/oauth/token
Scope: connections:read zatten:read zatten:write zatten:messages profile
Token Exchange: Default (POST Request)`;

    await navigator.clipboard.writeText(configText);
    setCopiedConfig(true);
    showToast('Parâmetros OAuth copiados para a área de transferência!');
    setTimeout(() => setCopiedConfig(false), 3000);
  };

  const filteredPermissions = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return permissions.filter(p => 
      p.name.toLowerCase().includes(term) || 
      p.id.toLowerCase().includes(term) || 
      p.description.toLowerCase().includes(term)
    );
  }, [permissions, searchTerm]);

  return (
    <div className="max-w-4xl mx-auto flex flex-col gap-8 pb-12 relative">
      {/* Toast flutuante de notificação */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div 
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            className="fixed top-6 right-6 z-50 flex items-center gap-3 bg-secondary/95 border border-border backdrop-blur-md px-4 py-3 rounded-xl shadow-2xl text-foreground text-sm font-medium"
          >
            <CheckCircle2 size={18} className="text-emerald-400 flex-shrink-0" />
            <span>{toastMessage}</span>
          </motion.div>
        )}
      </AnimatePresence>

      <div>
        <h2 className="text-3xl font-bold text-foreground tracking-tight">MCP Zatten</h2>
        <p className="text-zinc-400 mt-2">
          Gerencie o acesso e as permissões do seu agente de Inteligência Artificial via Model Context Protocol.
        </p>
      </div>

      {/* Card de Integração com o ChatGPT / Custom Actions */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-2xl p-6 md:p-8 border border-primary/20 relative overflow-hidden"
      >
        <div className="absolute top-0 right-0 w-96 h-96 bg-primary/5 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-4">
          <div className="flex items-start sm:items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500/20 to-primary/20 flex items-center justify-center border border-emerald-500/30 flex-shrink-0">
              <Sparkles className="text-emerald-400" size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-xl font-bold text-foreground">Conectar ao ChatGPT</h3>
                <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-medium flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  OAuth 2.1 Ativo
                </span>
              </div>
              <p className="text-sm text-zinc-400 mt-1">
                Servidor MCP e Custom Actions prontos com autenticação RFC 6749 / 8414 e isolamento de chaves Zatten.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <button
              type="button"
              onClick={handleCopyOpenApi}
              className="px-4 py-2.5 rounded-xl text-xs font-semibold bg-primary hover:bg-primary/90 text-primary-foreground shadow-lg shadow-primary/20 transition-all flex items-center gap-2 cursor-pointer active:scale-95"
            >
              {copiedOpenApi ? <Check size={14} className="text-emerald-300" /> : <Copy size={14} />}
              {copiedOpenApi ? 'Schema Copiado!' : 'Copiar Schema OpenAPI'}
            </button>

            <button
              type="button"
              onClick={handleCopyConfig}
              className="px-4 py-2.5 rounded-xl text-xs font-semibold bg-secondary hover:bg-secondary/80 text-foreground border border-border transition-all flex items-center gap-2 cursor-pointer active:scale-95"
            >
              {copiedConfig ? <Check size={14} className="text-emerald-300" /> : <Copy size={14} />}
              {copiedConfig ? 'Parâmetros Copiados!' : 'Copiar Dados OAuth'}
            </button>

            <a
              href="/openapi.json"
              target="_blank"
              rel="noopener noreferrer"
              className="px-3.5 py-2.5 rounded-xl text-xs font-semibold bg-secondary hover:bg-secondary/80 text-foreground border border-border transition-all flex items-center gap-1.5 cursor-pointer active:scale-95"
              title="Abrir especificação OpenAPI em nova aba"
            >
              <ExternalLink size={13} className="text-zinc-400" />
              <span>Ver Raw</span>
            </a>

            <button
              type="button"
              onClick={() => setShowChatGptInstructions(prev => !prev)}
              className="p-2.5 rounded-xl text-xs font-medium text-zinc-400 hover:text-foreground hover:bg-white/5 border border-border transition-colors flex items-center gap-1.5 cursor-pointer"
              title="Passo a Passo de Configuração"
            >
              <span className="text-xs">Tutorial</span>
              {showChatGptInstructions ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            </button>
          </div>
        </div>

        {/* Guia Expansível de Configuração no ChatGPT */}
        <AnimatePresence>
          {showChatGptInstructions && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="pt-6 border-t border-border flex flex-col gap-4 text-xs text-zinc-300 overflow-hidden"
            >
              <div className="grid md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-secondary/30 border border-border flex flex-col gap-2">
                  <div className="flex items-center gap-2 font-semibold text-foreground">
                    <span className="w-5 h-5 rounded-full bg-primary/20 text-primary text-[11px] flex items-center justify-center font-bold">1</span>
                    Criar GPT / Action
                  </div>
                  <p className="text-zinc-400 leading-relaxed">
                    No ChatGPT, vá em <strong>Explore GPTs</strong> &rarr; <strong>Create a GPT</strong> &rarr; <strong>Configure</strong> &rarr; <strong>Create new action</strong>.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-secondary/30 border border-border flex flex-col gap-2">
                  <div className="flex items-center gap-2 font-semibold text-foreground">
                    <span className="w-5 h-5 rounded-full bg-primary/20 text-primary text-[11px] flex items-center justify-center font-bold">2</span>
                    Importar OpenAPI Schema
                  </div>
                  <p className="text-zinc-400 leading-relaxed">
                    Clique em <strong>Copiar Schema OpenAPI</strong> acima e cole no campo <strong>Schema</strong> do Custom GPT, ou importe a URL <code>{window.location.origin}/openapi.json</code>.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-secondary/30 border border-border flex flex-col gap-2">
                  <div className="flex items-center gap-2 font-semibold text-foreground">
                    <span className="w-5 h-5 rounded-full bg-primary/20 text-primary text-[11px] flex items-center justify-center font-bold">3</span>
                    Configurar OAuth
                  </div>
                  <p className="text-zinc-400 leading-relaxed">
                    Em <strong>Authentication</strong>, selecione <strong>OAuth</strong>. Cole o Client ID, Auth URL, Token URL e Scopes.
                  </p>
                </div>
              </div>

              {/* Tabela de Parâmetros OAuth */}
              <div className="mt-2 p-4 rounded-xl bg-secondary/40 border border-border flex flex-col gap-3 font-mono text-[11px]">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-zinc-300">
                  <div>
                    <span className="text-zinc-500 font-sans block text-[10px]">Client ID:</span>
                    <span className="text-primary font-semibold select-all">chatgpt-firstsys-mcp</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 font-sans block text-[10px]">Client Secret:</span>
                    <span className="text-zinc-200 select-all">firstsys_chatgpt_mcp_secret_2026</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 font-sans block text-[10px]">Authorization URL:</span>
                    <span className="text-zinc-200 select-all">{window.location.origin}/oauth/authorize</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 font-sans block text-[10px]">Token URL:</span>
                    <span className="text-zinc-200 select-all">{window.location.origin}/oauth/token</span>
                  </div>
                  <div className="sm:col-span-2">
                    <span className="text-zinc-500 font-sans block text-[10px]">Scope:</span>
                    <span className="text-zinc-200 select-all">connections:read zatten:read zatten:write zatten:messages profile</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      <div className="grid md:grid-cols-4 gap-8">
        <div className="md:col-span-4 flex flex-col gap-6">
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass rounded-2xl p-6 md:p-8"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center border border-primary/30">
                  <Bot className="text-primary" size={24} />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-foreground">Ações do Agente</h3>
                  <p className="text-sm text-zinc-400">Ative ou desative as ferramentas disponíveis para a IA.</p>
                </div>
              </div>
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 w-full md:w-auto">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleEnableAll}
                    className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 transition-all flex items-center justify-center gap-1.5 cursor-pointer shadow-sm active:scale-95"
                  >
                    <Sparkles size={14} />
                    <span>Habilitar Todas (Acesso Total)</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleDisableAll}
                    className="px-3 py-2 rounded-xl text-xs font-medium text-zinc-400 hover:text-foreground hover:bg-white/5 border border-border transition-all flex items-center justify-center gap-1 cursor-pointer"
                  >
                    <X size={14} />
                    <span>Desabilitar Todas</span>
                  </button>
                </div>
                <div className="relative w-full sm:w-60">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" size={16} />
                  <input 
                    type="text" 
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Pesquisar ação..." 
                    className="w-full bg-secondary/50 border border-border focus:border-primary focus:ring-1 focus:ring-primary rounded-xl pl-9 pr-4 py-2 text-sm text-foreground outline-none transition-all"
                  />
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-4">
              <AnimatePresence>
                {filteredPermissions.length === 0 ? (
                  <motion.div 
                    initial={{ opacity: 0 }} 
                    animate={{ opacity: 1 }} 
                    className="p-8 text-center text-zinc-500"
                  >
                    Nenhuma ação encontrada para "{searchTerm}".
                  </motion.div>
                ) : (
                  filteredPermissions.map((perm) => (
                    <motion.div 
                      layout
                      initial={{ opacity: 0, scale: 0.98 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.98 }}
                      key={perm.id} 
                      className={`flex items-start justify-between p-5 rounded-xl border transition-colors ${
                        perm.enabled 
                          ? perm.danger ? 'bg-amber-500/5 border-amber-500/20' : 'bg-primary/5 border-primary/20' 
                          : 'bg-secondary/30 border-border/50'
                      }`}
                    >
                      <div className="flex flex-col gap-1 pr-6">
                        <div className="flex items-center gap-2">
                          <span className={`font-semibold ${perm.enabled ? 'text-foreground' : 'text-zinc-400'}`}>
                            {perm.name}
                          </span>
                          {perm.danger && (
                            <span className="inline-flex items-center gap-1 text-[10px] uppercase font-bold tracking-wider text-amber-500 bg-amber-500/10 px-2 py-0.5 rounded-full">
                              <ShieldAlert size={10} />
                              Sensível
                            </span>
                          )}
                        </div>
                        <p className={`text-sm ${perm.enabled ? 'text-zinc-300' : 'text-zinc-500'}`}>
                          {perm.description}
                        </p>
                      </div>

                      <button
                        type="button"
                        onClick={() => togglePermission(perm.id)}
                        className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none mt-1 ${
                          perm.enabled 
                            ? perm.danger ? 'bg-amber-500' : 'bg-primary' 
                            : 'bg-zinc-700'
                        }`}
                      >
                        <span
                          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                            perm.enabled ? 'translate-x-5' : 'translate-x-0'
                          }`}
                        >
                          {perm.enabled ? (
                            <Check className={`absolute inset-0 m-auto ${perm.danger ? 'text-amber-500' : 'text-primary'}`} size={12} strokeWidth={4} />
                          ) : (
                            <X className="absolute inset-0 m-auto text-zinc-400" size={12} strokeWidth={3} />
                          )}
                        </span>
                      </button>
                    </motion.div>
                  ))
                )}
              </AnimatePresence>
            </div>

            <div className="mt-8 p-4 bg-secondary/50 rounded-xl border border-border flex items-start gap-4">
              <Shield className="text-primary flex-shrink-0 mt-0.5" size={20} />
              <div>
                <h4 className="text-sm font-semibold text-foreground">Autorização Híbrida (OAuth + Connection Id)</h4>
                <p className="text-sm text-zinc-400 mt-1">
                  Mesmo que uma permissão esteja habilitada, o MCP solicitará confirmação humana para ações destrutivas ou de alto impacto, garantindo segurança 'Human-in-the-Loop'.
                </p>
              </div>
            </div>

            {/* Rodapé de Ações com Botão Salvar Alterações */}
            <div className="mt-8 pt-6 border-t border-border flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-3 text-xs text-zinc-400">
                <div className="flex items-center gap-1.5 font-mono">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <span>{enabledCount} de {permissions.length} ações ativas</span>
                </div>
                {hasUnsavedChanges && (
                  <span className="px-2.5 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[11px] font-medium flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                    Alterações não salvas
                  </span>
                )}
              </div>

              <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
                {hasUnsavedChanges && (
                  <button
                    type="button"
                    onClick={handleDiscardChanges}
                    disabled={isSaving}
                    className="px-4 py-2.5 rounded-xl text-sm font-medium text-zinc-400 hover:text-foreground hover:bg-white/5 border border-border transition-colors cursor-pointer flex items-center gap-2"
                  >
                    <RotateCcw size={15} />
                    Descartar
                  </button>
                )}

                <button
                  type="button"
                  id="save-mcp-permissions-btn"
                  onClick={handleSaveChanges}
                  disabled={isSaving}
                  className={`px-6 py-2.5 rounded-xl text-sm font-semibold transition-all duration-200 cursor-pointer flex items-center justify-center gap-2 shadow-lg active:scale-95 ${
                    hasUnsavedChanges
                      ? 'bg-primary hover:bg-primary/90 text-primary-foreground shadow-primary/30 ring-2 ring-primary/40 scale-[1.01]'
                      : 'bg-primary hover:bg-primary/90 text-primary-foreground shadow-primary/20'
                  }`}
                >
                  {isSaving ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      <span>Salvando...</span>
                    </>
                  ) : saveSuccess ? (
                    <>
                      <Check size={16} className="text-emerald-300" />
                      <span>Alterações Salvas!</span>
                    </>
                  ) : (
                    <>
                      <Save size={16} />
                      <span>Salvar Alterações</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Barra Fixa Flutuante quando houver alterações não salvas */}
      <AnimatePresence>
        {hasUnsavedChanges && (
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 40 }}
            className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 max-w-lg w-[calc(100%-2rem)] glass border border-primary/30 p-3.5 px-5 rounded-2xl shadow-2xl flex items-center justify-between gap-4 backdrop-blur-xl"
          >
            <div className="flex items-center gap-2.5 text-xs">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse" />
              <span className="text-foreground font-medium">Você possui alterações não salvas</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleDiscardChanges}
                disabled={isSaving}
                className="px-3 py-1.5 text-xs text-zinc-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors cursor-pointer"
              >
                Desfazer
              </button>
              <button
                type="button"
                onClick={handleSaveChanges}
                disabled={isSaving}
                className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-1.5 rounded-lg text-xs font-semibold shadow-md shadow-primary/20 transition-transform active:scale-95 cursor-pointer flex items-center gap-1.5"
              >
                {isSaving ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
                Salvar Alterações
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
