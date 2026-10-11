/**
 * CLIENTE E CONFIGURAÇÃO OAUTH 2.1 COM PKCE (RFC 7636)
 * Central de Chaves Zatten — Autenticação de Usuários e ChatGPT (Checklist 295)
 */

export interface OAuthConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  revocationEndpoint: string;
  userinfoEndpoint: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
}

export const OAUTH_PRODUCTION_CONFIG: OAuthConfig = {
  issuer: 'https://auth.firstsys.com.br',
  authorizationEndpoint: 'https://auth.firstsys.com.br/oauth/authorize',
  tokenEndpoint: 'https://auth.firstsys.com.br/oauth/token',
  revocationEndpoint: 'https://auth.firstsys.com.br/oauth/revoke',
  userinfoEndpoint: 'https://auth.firstsys.com.br/oauth/userinfo',
  clientId: 'zatten-central-production',
  redirectUri: 'https://keys.firstsys.com.br/oauth/callback',
  scopes: ['openid', 'profile', 'email', 'zatten:keys:read', 'zatten:keys:write']
};

export const OAUTH_DEVELOPMENT_CONFIG: OAuthConfig = {
  issuer: 'http://localhost:8080/auth',
  authorizationEndpoint: 'http://localhost:8080/auth/oauth/authorize',
  tokenEndpoint: 'http://localhost:8080/auth/oauth/token',
  revocationEndpoint: 'http://localhost:8080/auth/oauth/revoke',
  userinfoEndpoint: 'http://localhost:8080/auth/oauth/userinfo',
  clientId: 'zatten-central-dev',
  redirectUri: 'http://localhost:5173/oauth/callback',
  scopes: ['openid', 'profile', 'email', 'zatten:keys:read']
};

export function getOAuthConfig(): OAuthConfig {
  const isProd = import.meta.env.PROD || window.location.hostname !== 'localhost';
  return isProd ? OAUTH_PRODUCTION_CONFIG : OAUTH_DEVELOPMENT_CONFIG;
}

/**
 * Gera um Code Verifier de 64 caracteres de alta entropia para PKCE.
 */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(48);
  window.crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Calcula o Code Challenge derivado via SHA-256 (RFC 7636).
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hash));
  return btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Cria a URL completa de redirecionamento para o Servidor de Autorização.
 */
export async function createAuthorizationUrl(options?: {
  state?: string;
  customScope?: string[];
}): Promise<{ url: string; verifier: string; state: string }> {
  const config = getOAuthConfig();
  const verifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);
  const state = options?.state || generateCodeVerifier().slice(0, 32);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: (options?.customScope || config.scopes).join(' '),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state
  });

  return {
    url: `${config.authorizationEndpoint}?${params.toString()}`,
    verifier,
    state
  };
}

/**
 * Valida se uma URL de redirecionamento pertence à allowlist estrita do sistema.
 */
export function isValidRedirectUri(uri: string): boolean {
  const allowed = [
    OAUTH_PRODUCTION_CONFIG.redirectUri,
    OAUTH_DEVELOPMENT_CONFIG.redirectUri,
    'https://keys-staging.firstsys.com.br/oauth/callback'
  ];
  return allowed.includes(uri);
}
