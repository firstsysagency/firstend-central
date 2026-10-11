import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  Users, 
  Bell, 
  Lock, 
  QrCode, 
  Copy, 
  Check, 
  CheckCircle2, 
  RefreshCw, 
  Server, 
  X, 
  ShieldCheck, 
  AlertTriangle,
  KeyRound,
  Sliders,
  Smartphone,
  Loader2,
  LogIn
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { 
  formatSecretKey,
  generateQrCodeDataUrl
} from '../lib/totp';
import { 
  type OpenBaoConfig, 
  getOpenBaoConfig, 
  saveOpenBaoConfig, 
  rotateMasterKey 
} from '../lib/openbao';
import { useAuth } from '../context/AuthContext';
import MembersTab from '../components/settings/MembersTab';
import NotificationsTab from '../components/settings/NotificationsTab';
import AuditTab from '../components/settings/AuditTab';

export default function Settings() {
  // Aba ativa: 'security' | 'members' | 'notifications' | 'audit'
  const [activeTab, setActiveTab] = useState<'security' | 'members' | 'notifications' | 'audit'>('security');

  const { user, updateUser } = useAuth();
  const mfaEnabled = user?.twoFactorEnabled === true;
  const [isMfaModalOpen, setIsMfaModalOpen] = useState(false);
  const [isDisableMfaModalOpen, setIsDisableMfaModalOpen] = useState(false);

  // Estado OpenBao
  const [openBaoConfig, setOpenBaoConfig] = useState<OpenBaoConfig>(() => {
    return getOpenBaoConfig();
  });
  const [isOpenBaoModalOpen, setIsOpenBaoModalOpen] = useState(false);

  // Feedback Toast
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 3500);
  };

  const handleEnableMfaSuccess = () => {
    updateUser({ twoFactorEnabled: true });
    localStorage.setItem('zatten_settings_mfa', 'true');
    setIsMfaModalOpen(false);
    showToast('Autenticação em duas etapas (MFA) verificada e ativada com sucesso!');
  };

  const handleDisableMfa = async () => {
    try {
      const token = localStorage.getItem('zatten_token');
      await fetch('/api/2fa/disable', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
    } catch (e) {
      console.error(e);
    }
    updateUser({ twoFactorEnabled: false });
    localStorage.setItem('zatten_settings_mfa', 'false');
    localStorage.removeItem('zatten_settings_mfa_secret');
    setIsDisableMfaModalOpen(false);
    showToast('Autenticação em duas etapas desabilitada.');
  };

  const handleSaveOpenBao = (newConfig: OpenBaoConfig) => {
    setOpenBaoConfig(newConfig);
    saveOpenBaoConfig(newConfig);
    setIsOpenBaoModalOpen(false);
    showToast('Configurações do OpenBao atualizadas com sucesso.');
  };

  const handleRotateKeyNow = async () => {
    const result = await rotateMasterKey(openBaoConfig);
    const updated = getOpenBaoConfig();
    setOpenBaoConfig(updated);
    showToast(result.message);
  };

  return (
    <div className="max-w-4xl mx-auto flex flex-col gap-8 relative">
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
        <h2 className="text-3xl font-bold text-foreground tracking-tight">Configurações Gerais</h2>
        <p className="text-zinc-400 mt-2">Gerencie as preferências da sua organização, acessos e segurança.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
        <aside className="md:col-span-1 flex flex-col gap-2">
          <SettingsTab 
            active={activeTab === 'security'} 
            onClick={() => setActiveTab('security')} 
            icon={<Shield size={16} />} 
            label="Segurança" 
          />
          <SettingsTab 
            active={activeTab === 'members'} 
            onClick={() => setActiveTab('members')} 
            icon={<Users size={16} />} 
            label="Membros" 
          />
          <SettingsTab 
            active={activeTab === 'notifications'} 
            onClick={() => setActiveTab('notifications')} 
            icon={<Bell size={16} />} 
            label="Notificações" 
          />
          <SettingsTab 
            active={activeTab === 'audit'} 
            onClick={() => setActiveTab('audit')} 
            icon={<Lock size={16} />} 
            label="Auditoria" 
          />
        </aside>

        <div className="md:col-span-3 flex flex-col gap-6">
          {activeTab === 'security' && (
            <motion.div
              key="tab-security"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
              className="flex flex-col gap-6"
            >
              <div className="glass rounded-2xl p-6">
                <h3 className="text-xl font-semibold mb-4">Segurança da Organização</h3>
                <div className="flex flex-col gap-4">
                  
                  {/* Card 1: MFA */}
                  <div className="flex flex-col md:flex-row md:items-center justify-between p-4 bg-secondary/50 rounded-xl border border-border gap-4">
                    <div className="flex flex-col">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-foreground">Autenticação em duas etapas (MFA)</span>
                        {mfaEnabled ? (
                          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                            Habilitado
                          </span>
                        ) : (
                          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
                            Pendente
                          </span>
                        )}
                      </div>
                      <span className="text-sm text-zinc-400 mt-0.5">
                        {mfaEnabled 
                          ? 'Proteção TOTP ativada para sua conta e membros autorizados.'
                          : 'Exigir aplicativo autenticador (TOTP) para acesso administrativo.'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      {mfaEnabled ? (
                        <button 
                          type="button"
                          onClick={() => setIsDisableMfaModalOpen(true)}
                          className="bg-white/5 hover:bg-rose-500/10 text-zinc-300 hover:text-rose-400 border border-border px-4 py-2 rounded-lg text-sm font-medium transition-colors cursor-pointer"
                        >
                          Desativar
                        </button>
                      ) : (
                        <button 
                          type="button"
                          onClick={() => setIsMfaModalOpen(true)}
                          className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-2 rounded-lg text-sm font-medium transition-colors cursor-pointer flex items-center gap-2"
                        >
                          <QrCode size={15} />
                          Habilitar
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Card 2: Rotação no OpenBao */}
                  <div className="flex flex-col md:flex-row md:items-center justify-between p-4 bg-secondary/50 rounded-xl border border-border gap-4">
                    <div className="flex flex-col">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-foreground">Rotação de Chaves Mestra (OpenBao)</span>
                        <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
                          v{openBaoConfig.keyVersion} Ativa
                        </span>
                      </div>
                      <span className="text-sm text-zinc-400 mt-0.5">
                        Cofre Transit OpenBao: Rotação a cada {openBaoConfig.rotationInterval} dias. Última rotação: {openBaoConfig.lastRotatedAt}.
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button 
                        type="button"
                        onClick={() => setIsOpenBaoModalOpen(true)}
                        className="bg-white/5 hover:bg-white/10 text-foreground border border-border px-4 py-2 rounded-lg text-sm font-medium transition-colors cursor-pointer flex items-center gap-2"
                      >
                        <Sliders size={15} className="text-zinc-400" />
                        Configurar
                      </button>
                    </div>
                  </div>

                </div>
              </div>
              
              {/* Zona de Risco */}
              <div className="glass rounded-2xl p-6 border-rose-500/20">
                <h3 className="text-xl font-semibold mb-4 text-rose-500">Zona de Risco</h3>
                <div className="flex items-center justify-between p-4 bg-rose-500/5 rounded-xl border border-rose-500/20">
                  <div className="flex flex-col">
                    <span className="font-medium text-foreground">Excluir Organização</span>
                    <span className="text-sm text-zinc-400">Esta ação apagará todas as chaves e dados irreversivelmente.</span>
                  </div>
                  <button type="button" className="bg-rose-500 hover:bg-rose-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors cursor-pointer">
                    Excluir
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'members' && (
            <motion.div
              key="tab-members"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
            >
              <MembersTab onShowToast={showToast} />
            </motion.div>
          )}

          {activeTab === 'notifications' && (
            <motion.div
              key="tab-notifications"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
            >
              <NotificationsTab onShowToast={showToast} />
            </motion.div>
          )}

          {activeTab === 'audit' && (
            <motion.div
              key="tab-audit"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
            >
              <AuditTab onShowToast={showToast} />
            </motion.div>
          )}
        </div>
      </div>

      {/* MODAL CENTRAL: Habilitar MFA com Validação */}
      <AnimatePresence>
        {isMfaModalOpen && (
          <MfaEnableModal 
            onClose={() => setIsMfaModalOpen(false)}
            onSuccess={handleEnableMfaSuccess}
          />
        )}
      </AnimatePresence>

      {/* MODAL CENTRAL: Confirmar Desativação do MFA */}
      <AnimatePresence>
        {isDisableMfaModalOpen && (
          <ConfirmDisableMfaModal 
            onClose={() => setIsDisableMfaModalOpen(false)}
            onConfirm={handleDisableMfa}
          />
        )}
      </AnimatePresence>

      {/* MODAL CENTRAL: Configuração do OpenBao */}
      <AnimatePresence>
        {isOpenBaoModalOpen && (
          <OpenBaoModal 
            config={openBaoConfig}
            onClose={() => setIsOpenBaoModalOpen(false)}
            onSave={handleSaveOpenBao}
            onRotateNow={handleRotateKeyNow}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function SettingsTab({ 
  icon, 
  label, 
  active = false, 
  onClick 
}: { 
  icon: React.ReactNode; 
  label: string; 
  active?: boolean; 
  onClick: () => void; 
}) {
  return (
    <button 
      type="button" 
      onClick={onClick}
      className={`flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors text-left cursor-pointer ${
        active ? 'bg-primary/10 text-primary font-semibold' : 'text-zinc-400 hover:text-foreground hover:bg-white/5'
      }`}
    >
      {icon}
      {label}
    </button>
  );
}

// Modal Central para Habilitar e Validar MFA com TOTP RFC 6238 Real
function MfaEnableModal({ 
  onClose, 
  onSuccess 
}: { 
  onClose: () => void; 
  onSuccess: () => void; 
}) {
  const navigate = useNavigate();
  const { token, logout } = useAuth();
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [step, setStep] = useState<'scan' | 'verify'>('scan');
  const [isValidating, setIsValidating] = useState(false);
  const [isLoadingTotp, setIsLoadingTotp] = useState(true);
  const [isSessionExpired, setIsSessionExpired] = useState(false);
  
  // Segredo e QR Code real gerados para a sessão
  const [secret, setSecret] = useState<string>('');
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);
  const isInitiatingRef = useRef(false);

  const initTotp = async () => {
    setIsLoadingTotp(true);
    setError(null);
    setIsSessionExpired(false);
    setQrCodeDataUrl(null);
    setSecret('');

    try {
      const currentToken = token || localStorage.getItem('zatten_token');
      if (!currentToken) {
        setIsSessionExpired(true);
        setError('Sessão não identificada. Por favor, faça login novamente para habilitar o MFA com segurança.');
        setIsLoadingTotp(false);
        return;
      }

      // Usa proxy relativo /api/2fa/generate para compatibilidade total
      const res = await fetch('/api/2fa/generate', {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${currentToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (res.ok) {
        const data = await res.json();
        setSecret(data.secret);
        const qrData = await generateQrCodeDataUrl(data.otpauthUrl);
        setQrCodeDataUrl(qrData);
        setError(null);
      } else {
        const errData = await res.json().catch(() => null);
        if (res.status === 401) {
          setIsSessionExpired(true);
          setError(errData?.error || 'Sua sessão expirou ou é inválida. Faça login novamente para prosseguir com segurança.');
        } else {
          setError(errData?.error || `Erro ao gerar credenciais MFA (Status ${res.status}).`);
        }
      }
    } catch (e) {
      console.error('Erro de conexão ao inicializar 2FA:', e);
      setError('Não foi possível conectar ao servidor backend (porta 3000). Verifique se o serviço está ativo.');
    } finally {
      setIsLoadingTotp(false);
    }
  };

  useEffect(() => {
    if (isInitiatingRef.current) return;
    isInitiatingRef.current = true;
    initTotp();
  }, []);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const handleCopySecret = () => {
    if (!secret) return;
    navigator.clipboard.writeText(secret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  const handleVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCode = code.replace(/\D/g, '');
    if (cleanCode.length !== 6) {
      setError('O código autenticador deve conter exatamente 6 dígitos numéricos.');
      return;
    }

    setIsValidating(true);
    setError(null);

    try {
      const currentToken = token || localStorage.getItem('zatten_token');
      const res = await fetch('/api/2fa/verify', {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${currentToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token2fa: cleanCode, secret })
      });
      
      setIsValidating(false);

      if (res.ok) {
        onSuccess();
      } else {
        const data = await res.json().catch(() => null);
        if (res.status === 401) {
          setIsSessionExpired(true);
          setError(data?.error || 'Sessão expirada. Faça login novamente.');
        } else {
          setError(data?.error || 'Código incorreto ou expirado. Verifique o relógio do seu dispositivo.');
        }
      }
    } catch (e) {
      setIsValidating(false);
      setError('Erro ao comunicar com o servidor. Tente novamente.');
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
        transition={{ type: 'spring', damping: 25, stiffness: 300 }}
        className="glass max-w-lg w-full rounded-2xl p-6 border border-border shadow-2xl relative overflow-hidden cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <ShieldCheck size={20} />
            </div>
            <div>
              <h4 className="text-xl font-bold text-foreground">Autenticação em Duas Etapas</h4>
              <p className="text-xs text-zinc-400">Validação Real RFC 6238 (Google Authenticator, Authy, etc.)</p>
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

        {step === 'scan' ? (
          <div className="flex flex-col gap-6 mt-6">
            <div className="flex flex-col items-center justify-center p-6 bg-secondary/40 rounded-2xl border border-border text-center">
              {/* Box do QR Code com Estados Reais */}
              <div className="p-3 bg-white rounded-xl shadow-lg mb-3 flex items-center justify-center min-w-[200px] min-h-[200px] relative">
                {qrCodeDataUrl ? (
                  <motion.img 
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    src={qrCodeDataUrl} 
                    alt="QR Code Autenticador TOTP" 
                    className="w-48 h-48 block rounded-lg"
                  />
                ) : isLoadingTotp ? (
                  <div className="flex flex-col items-center gap-2 text-zinc-500 py-12 px-4">
                    <Loader2 size={26} className="animate-spin text-primary" />
                    <span className="text-xs font-mono font-medium text-zinc-700">Gerando QR Code real...</span>
                    <span className="text-[10px] text-zinc-400">Sincronizando com RFC 6238</span>
                  </div>
                ) : (
                  <div className="flex flex-col items-center gap-2 text-amber-600 py-10 px-4 max-w-[200px]">
                    <AlertTriangle size={32} className="text-amber-500" />
                    <span className="text-xs font-medium text-center">Não foi possível gerar o QR Code</span>
                  </div>
                )}
              </div>

              {/* Bloco de Mensagem de Erro ou Instrução */}
              {error && (
                <div className="w-full mb-3 p-3.5 bg-amber-500/10 border border-amber-500/20 rounded-xl flex flex-col gap-2.5 text-left">
                  <div className="flex items-start gap-2.5 text-xs text-amber-300">
                    <AlertTriangle size={16} className="text-amber-400 flex-shrink-0 mt-0.5" />
                    <span className="leading-relaxed">{error}</span>
                  </div>
                  <div className="flex items-center gap-2 pt-1 border-t border-amber-500/15">
                    {isSessionExpired ? (
                      <button
                        type="button"
                        onClick={() => {
                          logout();
                          navigate('/login');
                        }}
                        className="flex items-center gap-1.5 text-xs bg-primary hover:bg-primary/90 text-primary-foreground px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer shadow-md shadow-primary/20"
                      >
                        <LogIn size={13} />
                        <span>Fazer Login Novamente</span>
                      </button>
                    ) : null}
                    <button
                      type="button"
                      onClick={() => {
                        isInitiatingRef.current = false;
                        initTotp();
                      }}
                      className="flex items-center gap-1.5 text-xs bg-white/10 hover:bg-white/15 text-white px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer"
                    >
                      <RefreshCw size={13} />
                      <span>Tentar Novamente</span>
                    </button>
                  </div>
                </div>
              )}

              {!error && (
                <>
                  <p className="text-xs text-zinc-300 max-w-xs font-medium">
                    Abra a câmera ou o app autenticador no seu celular e escaneie o código acima.
                  </p>
                  <span className="text-[11px] text-zinc-500 mt-1">
                    Compatível com Google Authenticator, Microsoft Authenticator, 1Password e Authy.
                  </span>
                </>
              )}
            </div>

            <div className="flex flex-col gap-2">
              <label className="text-xs font-medium text-zinc-400">Ou insira a chave secreta manualmente no aplicativo:</label>
              <div className="flex items-center justify-between p-3 bg-secondary rounded-xl border border-border">
                <code className="text-sm font-mono text-primary font-bold tracking-wider">
                  {secret 
                    ? formatSecretKey(secret) 
                    : isLoadingTotp 
                      ? 'Gerando chave...' 
                      : 'Indisponível no momento'}
                </code>
                <button
                  type="button"
                  onClick={handleCopySecret}
                  disabled={!secret || isLoadingTotp}
                  className="flex items-center gap-1.5 text-xs text-zinc-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed px-2.5 py-1 rounded-lg hover:bg-white/5 transition-colors cursor-pointer"
                >
                  {copiedSecret ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                  <span>{copiedSecret ? 'Copiado!' : 'Copiar'}</span>
                </button>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2.5 rounded-xl text-sm font-medium text-zinc-400 hover:text-foreground hover:bg-white/5 border border-border transition-colors cursor-pointer"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={() => setStep('verify')}
                disabled={!secret || isLoadingTotp || !!error}
                className="bg-primary hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed text-primary-foreground px-5 py-2.5 rounded-xl text-sm font-medium transition-colors cursor-pointer shadow-lg shadow-primary/20 flex items-center gap-2"
              >
                <span>Avançar para Validação</span>
                <Smartphone size={16} />
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleVerifyCode} className="flex flex-col gap-6 mt-6">
            <div className="flex flex-col gap-2">
              <label className="text-sm font-medium text-zinc-300">
                Digite o Código de 6 Dígitos do seu Celular
              </label>
              <p className="text-xs text-zinc-400">
                Insira o código numérico gerado no aplicativo autenticador para validar a sincronização temporal (RFC 6238).
              </p>
              <input 
                type="text" 
                inputMode="numeric"
                maxLength={6}
                value={code}
                onChange={(e) => {
                  setCode(e.target.value.replace(/\D/g, ''));
                  setError(null);
                }}
                autoFocus
                placeholder="000000"
                className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-3.5 text-center text-3xl font-mono tracking-[0.35em] text-foreground focus:outline-none focus:ring-2 transition-all mt-2"
              />
              {error && (
                <div className="flex items-start gap-2 p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 text-xs mt-1 leading-relaxed">
                  <AlertTriangle size={15} className="flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}
            </div>

            <div className="p-3 bg-primary/10 rounded-xl border border-primary/20 flex items-start gap-2.5 text-xs text-primary-foreground/80 leading-relaxed">
              <KeyRound size={16} className="text-primary flex-shrink-0 mt-0.5" />
              <span>
                Esta é uma validação criptográfica real. O código só será aceito se for válido para o segredo gerado e estiver dentro da janela de tempo atual.
              </span>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-border">
              <button
                type="button"
                onClick={() => setStep('scan')}
                className="text-xs text-zinc-400 hover:text-foreground transition-colors cursor-pointer"
              >
                ← Voltar ao QR Code
              </button>
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2.5 rounded-xl text-sm font-medium text-zinc-400 hover:text-foreground hover:bg-white/5 border border-border transition-colors cursor-pointer"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={isValidating || code.length !== 6}
                  className="bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-white px-5 py-2.5 rounded-xl text-sm font-medium transition-colors shadow-lg shadow-emerald-500/20 active:scale-95 cursor-pointer flex items-center gap-2"
                >
                  {isValidating ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      Validando...
                    </>
                  ) : (
                    <>
                      <Check size={16} />
                      Confirmar e Ativar MFA
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>
        )}
      </motion.div>
    </div>
  );
}

// Modal para Desativar MFA
function ConfirmDisableMfaModal({
  onClose,
  onConfirm
}: {
  onClose: () => void;
  onConfirm: () => void;
}) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
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
        className="glass max-w-md w-full rounded-2xl p-6 border border-rose-500/30 shadow-2xl relative overflow-hidden cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center flex-shrink-0 text-rose-400">
            <AlertTriangle size={24} />
          </div>
          <div className="flex-1">
            <h4 className="text-xl font-bold text-foreground">Desativar Autenticação em Duas Etapas?</h4>
            <p className="text-zinc-400 text-sm mt-2 leading-relaxed">
              Sua conta ficará protegida apenas por senha. Esta ação reduz o nível de segurança da organização.
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
            Sim, Desativar MFA
          </button>
        </div>
      </motion.div>
    </div>
  );
}

// Modal de Configuração da Rotação da Chave Mestra com OpenBao
function OpenBaoModal({
  config,
  onClose,
  onSave,
  onRotateNow
}: {
  config: OpenBaoConfig;
  onClose: () => void;
  onSave: (newConfig: OpenBaoConfig) => void;
  onRotateNow: () => void;
}) {
  const [vaultUrl, setVaultUrl] = useState(config.vaultUrl);
  const [transitPath, setTransitPath] = useState(config.transitPath);
  const [token, setToken] = useState(config.token || '');
  const [rotationInterval, setRotationInterval] = useState(config.rotationInterval);
  const [autoRotation, setAutoRotation] = useState(config.autoRotation);
  const [isRotating, setIsRotating] = useState(false);
  const [currentVersion, setCurrentVersion] = useState(config.keyVersion);
  const [lastRotated, setLastRotated] = useState(config.lastRotatedAt);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    onSave({
      ...config,
      vaultUrl,
      transitPath,
      token,
      rotationInterval,
      autoRotation,
      keyVersion: currentVersion,
      lastRotatedAt: lastRotated
    });
  };

  const handleTriggerRotation = async () => {
    setIsRotating(true);
    const draftConfig: OpenBaoConfig = {
      ...config,
      vaultUrl,
      transitPath,
      token,
      rotationInterval,
      autoRotation,
      keyVersion: currentVersion,
      lastRotatedAt: lastRotated
    };
    const result = await rotateMasterKey(draftConfig);
    setCurrentVersion(result.newVersion);
    const now = new Date();
    const dateStr = now.toLocaleDateString('pt-BR') + ' às ' + now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
    setLastRotated(dateStr);
    setIsRotating(false);
    onRotateNow();
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
              <Server size={20} />
            </div>
            <div>
              <h4 className="text-xl font-bold text-foreground">Configuração do OpenBao</h4>
              <p className="text-xs text-zinc-400">Gerenciamento e Rotação de Chaves Mestras (KMS / Transit)</p>
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

        <form onSubmit={handleSave} className="flex flex-col gap-5 mt-5">
          {/* Card de Status da Versão Atual */}
          <div className="p-4 bg-secondary/50 rounded-xl border border-border flex items-center justify-between">
            <div className="flex flex-col">
              <span className="text-xs text-zinc-400">Versão da Chave Mestra Ativa</span>
              <span className="text-lg font-bold font-mono text-primary mt-0.5">
                v{currentVersion} (AES-256-GCM)
              </span>
              <span className="text-[11px] text-zinc-500 mt-1">Última rotação executada: {lastRotated}</span>
            </div>
            <button
              type="button"
              disabled={isRotating}
              onClick={handleTriggerRotation}
              className="bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 px-3.5 py-2 rounded-xl text-xs font-semibold transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-50"
              title="Gera uma nova versão da chave mestra no OpenBao e atualiza o envelope criptográfico"
            >
              <RefreshCw size={14} className={isRotating ? 'animate-spin' : ''} />
              {isRotating ? 'Rotacionando...' : 'Rotacionar Agora'}
            </button>
          </div>

          {/* Endpoint OpenBao */}
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-zinc-300">Endpoint Interno do OpenBao (Vault URL)</label>
            <input 
              type="text" 
              value={vaultUrl}
              onChange={(e) => setVaultUrl(e.target.value)}
              required
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground font-mono focus:outline-none focus:ring-2 transition-all text-sm"
              placeholder="https://vault.internal:8200"
            />
            <span className="text-xs text-zinc-500">Endereço de rede isolada Docker / VPS sem exposição pública.</span>
          </div>

          {/* Token de Autenticação OpenBao */}
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-zinc-300">Token de Acesso (X-Vault-Token)</label>
            <input 
              type="password" 
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground font-mono focus:outline-none focus:ring-2 transition-all text-sm"
              placeholder="s.xxxxxxxxxxxx ou hvs.xxxxxxxxxxxx"
            />
            <span className="text-xs text-zinc-500">Token com permissões na rota Transit. Mantido de forma segura localmente.</span>
          </div>

          {/* Caminho da Engine Transit */}
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-zinc-300">Caminho da Chave Mestra (Transit Secrets Engine)</label>
            <input 
              type="text" 
              value={transitPath}
              onChange={(e) => setTransitPath(e.target.value)}
              required
              className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground font-mono focus:outline-none focus:ring-2 transition-all text-sm"
              placeholder="transit/keys/key-manager-master"
            />
          </div>

          {/* Intervalo de Rotação Automática */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-sm font-medium text-zinc-300">Intervalo de Rotação Automática</label>
              <select
                value={rotationInterval}
                onChange={(e) => setRotationInterval(e.target.value)}
                className="bg-secondary border border-border focus:ring-primary focus:border-transparent rounded-xl px-4 py-2.5 text-foreground focus:outline-none focus:ring-2 transition-all text-sm cursor-pointer"
              >
                <option value="30">A cada 30 dias (Alta frequência)</option>
                <option value="60">A cada 60 dias</option>
                <option value="90">A cada 90 dias (Recomendado)</option>
                <option value="180">A cada 180 dias</option>
                <option value="365">A cada 365 dias (Anual)</option>
                <option value="manual">Apenas Rotação Manual</option>
              </select>
            </div>

            <div className="flex flex-col gap-1.5 justify-center">
              <label className="text-sm font-medium text-zinc-300">Agendamento de Rotação</label>
              <label className="flex items-center gap-3 p-2.5 bg-secondary/60 rounded-xl border border-border cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={autoRotation}
                  onChange={(e) => setAutoRotation(e.target.checked)}
                  className="rounded border-zinc-700 text-primary focus:ring-primary h-4 w-4 cursor-pointer"
                />
                <span className="text-xs text-zinc-300 font-medium">Habilitar rotina automática</span>
              </label>
            </div>
          </div>

          {/* Diretriz de Envelope Encryption */}
          <div className="p-3 bg-primary/10 rounded-xl border border-primary/20 flex items-start gap-2.5 text-xs text-primary-foreground/80 leading-relaxed">
            <ShieldCheck size={16} className="text-primary flex-shrink-0 mt-0.5" />
            <span>
              <strong>Envelope Encryption:</strong> Ao rotacionar a chave no OpenBao, chaves de dados anteriores continuam decifráveis com versões antigas, enquanto novas conexões passam a ser cifradas com a versão mais recente.
            </span>
          </div>

          {/* Ações */}
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
              className="bg-primary hover:bg-primary/90 text-primary-foreground px-5 py-2.5 rounded-xl text-sm font-medium transition-colors shadow-lg shadow-primary/20 active:scale-95 cursor-pointer"
            >
              Salvar Configurações
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}

