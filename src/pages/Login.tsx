import { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, KeyRound, Loader2, User } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token2fa, setToken2fa] = useState('');
  const [needs2FA, setNeeds2FA] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, token2fa: needs2FA ? token2fa : undefined }),
      });

      if (response.status === 206) {
        setNeeds2FA(true);
        setIsLoading(false);
        return;
      }

      if (!response.ok) {
        // Mensagem sempre genérica conforme solicitado
        setError('Credenciais inválidas.');
        setIsLoading(false);
        return;
      }

      const data = await response.json();
      if (data.success && data.token) {
        login(data.token, data.user);
        navigate('/');
      }
    } catch (err) {
      setError('Credenciais inválidas.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <div className="flex flex-col items-center justify-center gap-4 mb-8">
          <div className="w-16 h-16 rounded-2xl bg-primary flex items-center justify-center shadow-lg shadow-primary/20">
            <KeyRound className="text-primary-foreground" size={32} />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold text-foreground">Central Zatten</h1>
            <p className="text-zinc-400 mt-1 text-sm">Autentique-se para continuar</p>
          </div>
        </div>

        <div className="glass rounded-2xl p-8 border border-border">
          <form onSubmit={handleSubmit} className="flex flex-col gap-6">
            
            {error && (
              <div className="bg-rose-500/10 border border-rose-500/20 text-rose-500 text-sm px-4 py-3 rounded-xl text-center">
                {error}
              </div>
            )}

            {!needs2FA ? (
              <>
                <div className="flex flex-col gap-2">
                  <label className="text-sm font-medium text-zinc-300 ml-1">E-mail</label>
                  <div className="relative">
                    <User className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500" size={18} />
                    <input 
                      type="email" 
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full bg-secondary border border-border focus:ring-primary rounded-xl pl-12 pr-4 py-3 text-foreground focus:outline-none focus:ring-2 focus:border-transparent transition-all"
                      placeholder="usuario@dominio.com"
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-2">
                  <label className="text-sm font-medium text-zinc-300 ml-1">Senha</label>
                  <div className="relative">
                    <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500" size={18} />
                    <input 
                      type="password" 
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full bg-secondary border border-border focus:ring-primary rounded-xl pl-12 pr-4 py-3 text-foreground focus:outline-none focus:ring-2 focus:border-transparent transition-all"
                      placeholder="••••••••"
                    />
                  </div>
                </div>
              </>
            ) : (
              <div className="flex flex-col gap-4">
                <div className="text-center mb-2">
                  <Shield className="mx-auto text-primary mb-2" size={32} />
                  <p className="text-sm text-zinc-300">Digite o código de 6 dígitos gerado pelo seu aplicativo autenticador.</p>
                </div>
                <div className="flex flex-col gap-2">
                  <input 
                    type="text" 
                    required
                    maxLength={6}
                    value={token2fa}
                    onChange={(e) => setToken2fa(e.target.value.replace(/[^0-9]/g, ''))}
                    className="w-full text-center tracking-[0.5em] font-mono text-xl bg-secondary border border-border focus:ring-primary rounded-xl px-4 py-4 text-foreground focus:outline-none focus:ring-2 focus:border-transparent transition-all"
                    placeholder="000000"
                  />
                </div>
              </div>
            )}

            <button 
              type="submit" 
              disabled={isLoading}
              className="mt-2 w-full bg-primary hover:bg-primary/90 text-primary-foreground px-6 py-3.5 rounded-xl font-medium transition-all active:scale-[0.98] flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <Loader2 className="animate-spin" size={18} />
              ) : (
                'Entrar'
              )}
            </button>
          </form>
        </div>
      </motion.div>
    </div>
  );
}
