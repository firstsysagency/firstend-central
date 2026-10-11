-- ==============================================================================
-- SCHEMA POSTGRESQL & ROW LEVEL SECURITY (RLS)
-- Central Privada de Conexões Zatten — Firstsys
-- ==============================================================================

-- Extensões para UUID criptográfico e pgcrypto
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. ORGANIZAÇÕES
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. USUÁRIOS
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    failed_login_attempts INT DEFAULT 0,
    lock_until TIMESTAMP WITH TIME ZONE,
    token_version INT DEFAULT 1,
    status VARCHAR(32) DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. MEMBROS DA ORGANIZAÇÃO (RBAC)
CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, user_id)
);

-- 4. CONEXÕES ZATTEN (Chave NUNCA em texto aberto: apenas secret_ref do OpenBao/AES-GCM)
CREATE TABLE IF NOT EXISTS connections (
    id VARCHAR(64) PRIMARY KEY, -- ID opaco não previsível (ex: conn_01j7...)
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    secret_ref VARCHAR(255) NOT NULL, -- Referência cifrada no cofre OpenBao / AES-GCM
    key_version INT DEFAULT 1,
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'invalid', 'paused', 'revoked')),
    last_validated_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(64) NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. CLIENTES OAUTH 2.1 (ChatGPT, Painel Web)
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL, -- Array de URLs estritas sem curinga
    is_confidential BOOLEAN DEFAULT FALSE,
    allowed_scopes TEXT[] NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. CÓDIGOS DE AUTORIZAÇÃO TEMPORÁRIOS (PKCE S256)
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code VARCHAR(128) PRIMARY KEY,
    client_id VARCHAR(128) NOT NULL REFERENCES oauth_clients(client_id),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id),
    redirect_uri TEXT NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(16) NOT NULL DEFAULT 'S256',
    scope TEXT NOT NULL,
    resource TEXT,
    nonce VARCHAR(128),
    consumed BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. REFRESH TOKENS E FAMÍLIAS DE ROTAÇÃO (Token Family Reuse Detection)
CREATE TABLE IF NOT EXISTS oauth_refresh_families (
    token VARCHAR(128) PRIMARY KEY,
    family_id VARCHAR(64) NOT NULL,
    client_id VARCHAR(128) NOT NULL REFERENCES oauth_clients(client_id),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id),
    scope TEXT NOT NULL,
    resource TEXT,
    consumed BOOLEAN DEFAULT FALSE,
    revoked BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_family_id ON oauth_refresh_families(family_id);

-- 8. TRILHA DE AUDITORIA IMUTÁVEL (Append-Only)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id VARCHAR(64),
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL CHECK (LOWER(severity) IN ('info', 'warning', 'critical')),
    description TEXT NOT NULL,
    ip VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================================================
-- POLÍTICAS DE ROW LEVEL SECURITY (RLS) MILITARES
-- ==============================================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Impedir qualquer UPDATE ou DELETE na trilha de auditoria (Imutabilidade estrita)
CREATE OR REPLACE FUNCTION trg_prevent_audit_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Operação não permitida: A trilha de auditoria da Firstsys é imutável e append-only.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_tampering ON audit_logs;
CREATE TRIGGER trg_audit_tampering
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_tampering();
