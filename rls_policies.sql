-- =========================================================================
-- Arquivo: rls_policies.sql
-- Descrição: Políticas de Row-Level Security (RLS) para o PostgreSQL
-- =========================================================================

-- Ativar RLS nas tabelas principais
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- =========================================================================
-- TABELA: users
-- Regras:
-- 1. Um usuário só pode ver seus próprios dados (exceto administradores).
-- 2. Administradores/DONO podem ver todos os usuários.
-- =========================================================================

-- Permitir que usuários vejam seu próprio registro
CREATE POLICY "Users can view their own profile" 
ON users
FOR SELECT
USING (auth.uid() = id);

-- Permitir que usuários com role 'DONO' vejam todos os usuários
CREATE POLICY "DONO can view all users"
ON users
FOR SELECT
USING (
  EXISTS (
    SELECT 1 FROM users WHERE id = auth.uid() AND role = 'DONO'
  )
);

-- =========================================================================
-- TABELA: connections
-- Regras:
-- 1. Apenas usuários autenticados (qualquer um logado) podem ler conexões ativas.
-- 2. Apenas role 'DONO' ou 'ADMIN' pode criar ou editar conexões.
-- =========================================================================

-- Leitura de conexões permitida para quem está logado
CREATE POLICY "Authenticated users can read connections"
ON connections
FOR SELECT
USING (auth.role() = 'authenticated');

-- Inserção permitida apenas para DONO ou ADMIN
CREATE POLICY "Only DONO/ADMIN can insert connections"
ON connections
FOR INSERT
WITH CHECK (
  EXISTS (
    SELECT 1 FROM users 
    WHERE id = auth.uid() 
    AND (role = 'DONO' OR role = 'ADMIN')
  )
);

-- Atualização/Exclusão (Revogar chave) apenas para DONO ou ADMIN
CREATE POLICY "Only DONO/ADMIN can update or delete connections"
ON connections
FOR ALL
USING (
  EXISTS (
    SELECT 1 FROM users 
    WHERE id = auth.uid() 
    AND (role = 'DONO' OR role = 'ADMIN')
  )
);

-- =========================================================================
-- TABELA: audit_logs (Tabela Imutável)
-- Regras:
-- 1. Inserção (INSERT) permitida para o servidor/backend.
-- 2. Leitura (SELECT) restrita aos auditores ou DONO.
-- 3. Atualização/Deleção TOTALMENTE NEGADAS para garantir imutabilidade.
-- =========================================================================

-- Inserção de log: Dependendo de como o backend conecta, se for service_role, ele burla RLS.
-- Caso seja inserido via usuário autenticado, permite o INSERT
CREATE POLICY "Anyone can insert audit logs"
ON audit_logs
FOR INSERT
WITH CHECK (auth.role() = 'authenticated');

-- Leitura de logs restrita ao DONO
CREATE POLICY "Only DONO can view audit logs"
ON audit_logs
FOR SELECT
USING (
  EXISTS (
    SELECT 1 FROM users 
    WHERE id = auth.uid() 
    AND role = 'DONO'
  )
);

-- Proibir UPDATE explicitamente
CREATE POLICY "Prohibit UPDATE on audit logs"
ON audit_logs
FOR UPDATE
USING (false);

-- Proibir DELETE explicitamente
CREATE POLICY "Prohibit DELETE on audit logs"
ON audit_logs
FOR DELETE
USING (false);
