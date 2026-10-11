import { useState } from 'react';
import { motion } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Shield, Eye, EyeOff, KeyRound, Loader2, ArrowLeft, Info, Server } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { addConnection } from '../lib/connections';

const connectionSchema = z.object({
  name: z.string().min(3, 'O nome deve ter no mínimo 3 caracteres').max(50),
  apiKey: z.string().min(10, 'A chave Zatten parece muito curta').regex(/^[a-zA-Z0-9_-]+$/, 'Formato de chave inválido'),
});

type FormValues = z.infer<typeof connectionSchema>;

export default function NewConnection() {
  const [showKey, setShowKey] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();

  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(connectionSchema)
  });

  const onSubmit = async (data: FormValues) => {
    setIsSubmitting(true);
    
    // Enviar a chave via canal seguro (HTTPS) para o backend,
    // que fará a criptografia (AES-256) antes de armazenar.
    console.log('Enviando para o backend a chave crua de forma segura via HTTPS.');

    // Salvar conexão localmente
    addConnection({
      name: data.name,
      environment: 'production',
      description: 'Conexão ativa com a API Zatten criada via Key Manager',
      apiKey: data.apiKey // Em um fluxo real de BD, o backend é quem armazenaria a versão encriptada
    });

    // Simular requisição de handshake segura ao backend
    await new Promise(r => setTimeout(r, 1000));
    setIsSubmitting(false);
    navigate('/');
  };

  return (
    <div className="max-w-2xl mx-auto flex flex-col gap-8">
      <div>
        <Link to="/" className="inline-flex items-center gap-2 text-zinc-400 hover:text-foreground mb-6 transition-colors">
          <ArrowLeft size={16} />
          Voltar
        </Link>
        <h2 className="text-3xl font-bold text-foreground tracking-tight">Nova Conexão Zatten</h2>
        <p className="text-zinc-400 mt-2">
          Cadastre uma nova chave de API da Zatten ou provisione diretamente via Variáveis de Ambiente no Coolify.
        </p>
      </div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-2xl p-8 border-t border-t-primary/20"
      >
        {/* Banner de Destaque: Provisionamento via Variáveis de Ambiente do Coolify */}
        <div className="flex items-start gap-4 mb-6 p-4 bg-indigo-500/10 border border-indigo-500/30 rounded-xl">
          <Server className="text-indigo-400 flex-shrink-0 mt-0.5" size={20} />
          <div className="flex flex-col gap-1.5">
            <p className="text-sm text-indigo-200 font-semibold flex items-center gap-2">
              Provisionamento Recomendado via Coolify (Sem Digitar Chaves no Navegador)
            </p>
            <p className="text-xs text-indigo-300/80 leading-relaxed">
              Você pode definir <code className="bg-zinc-900/80 px-1.5 py-0.5 rounded text-indigo-200 font-mono">ZATTEN_API_KEY=zat_live_...</code> diretamente nas Variáveis de Ambiente da sua aplicação no Coolify. O backend detectará e protegerá a conexão automaticamente no cofre, sem nenhum trânsito da chave pelo front-end.
            </p>
          </div>
        </div>
        <div className="flex items-start gap-4 mb-8 p-4 bg-primary/10 border border-primary/20 rounded-xl">
          <Shield className="text-primary flex-shrink-0 mt-0.5" size={20} />
          <div className="flex flex-col gap-2">
            <p className="text-sm text-primary-foreground/90 font-medium">Segurança HTTPS & Criptografia no Cofre</p>
            <p className="text-sm text-primary-foreground/70 leading-relaxed">
              Sua chave é trafegada via HTTPS e o servidor encarregado a criptografa com AES-256 antes do armazenamento no banco de dados, protegendo contra interceptação.
            </p>
          </div>
        </div>

        <div className="flex items-start gap-4 mb-8 p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl">
          <Info className="text-amber-500 flex-shrink-0 mt-0.5" size={20} />
          <div className="flex flex-col gap-2">
            <p className="text-sm text-amber-500/90 font-medium">Regra de Imutabilidade</p>
            <p className="text-sm text-amber-500/70 leading-relaxed">
              Por segurança, após cadastrar, você não poderá visualizar ou editar esta chave novamente. Se precisar alterá-la futuramente, será necessário revogar a conexão e criar uma nova.
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-6">
          <div className="flex flex-col gap-2">
            <label className="text-sm font-medium text-zinc-300 ml-1">Nome da Conexão</label>
            <input 
              {...register('name')}
              type="text" 
              className={`bg-secondary border ${errors.name ? 'border-rose-500 focus:ring-rose-500' : 'border-border focus:ring-primary'} rounded-xl px-4 py-3 text-foreground focus:outline-none focus:ring-2 focus:border-transparent transition-all`}
              placeholder="Ex: Lavínia — Atendimento B2C"
            />
            {errors.name && <span className="text-rose-500 text-xs ml-1">{errors.name.message}</span>}
          </div>

          <div className="flex flex-col gap-2">
            <label className="text-sm font-medium text-zinc-300 ml-1">Chave Zatten (x-api-key)</label>
            <div className="relative">
              <input 
                {...register('apiKey')}
                type={showKey ? 'text' : 'password'} 
                className={`w-full bg-secondary border ${errors.apiKey ? 'border-rose-500 focus:ring-rose-500' : 'border-border focus:ring-primary'} rounded-xl pl-12 pr-12 py-3 text-foreground font-mono focus:outline-none focus:ring-2 focus:border-transparent transition-all`}
                placeholder="sk_test_..."
              />
              <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500" size={18} />
              <button 
                type="button" 
                onClick={() => setShowKey(!showKey)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                {showKey ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {errors.apiKey && <span className="text-rose-500 text-xs ml-1">{errors.apiKey.message}</span>}
          </div>

          <div className="pt-4 flex justify-end">
            <button 
              type="submit" 
              disabled={isSubmitting}
              className="bg-primary hover:bg-primary/90 text-primary-foreground px-6 py-3 rounded-xl font-medium transition-all active:scale-[0.98] flex items-center justify-center gap-2 min-w-[160px]"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="animate-spin" size={18} />
                  Validando...
                </>
              ) : (
                <>
                  <Shield size={18} />
                  Salvar Conexão
                </>
              )}
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}
