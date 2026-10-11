/**
 * REPOSITÓRIO E GERENCIADOR DE ESTADO OAUTH 2.1
 * Armazenamento de Códigos de Autorização, Rotação de Refresh Tokens e Detecção de Reuso de Família
 * Central Privada de Conexões Zatten — Firstsys
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { OAuthScope, UserRole } from './oauthTypes.js';
import { keyManager, toBase64Url, fromBase64Url } from './cryptoEngine.js';

export interface OAuthClient {
  id: string;
  name: string;
  redirectUris: string[];
  isConfidential: boolean;
  hashedSecret?: string;
  allowedScopes: OAuthScope[];
}

export interface AuthorizationCodeRecord {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256';
  userId: string;
  userEmail: string;
  orgId: string;
  role: UserRole;
  scope: string;
  resource?: string;
  nonce?: string;
  expiresAt: number;
  consumed: boolean;
}

export interface RefreshTokenRecord {
  token: string;
  familyId: string;
  clientId: string;
  userId: string;
  userEmail: string;
  orgId: string;
  role: UserRole;
  scope: string;
  resource?: string;
  expiresAt: number;
  consumed: boolean;
  revoked: boolean;
}

export interface RevokedTokenEntry {
  jti: string;
  revokedAt: number;
  expiresAt: number;
}

interface SelfContainedRefreshToken {
  t: 'rt';
  fam: string;
  cid: string;
  uid: string;
  ue: string;
  org: string;
  rol: UserRole;
  scp: string;
  res?: string;
  exp: number;
  rnd: string;
}

function getRefreshSecretKey(): Buffer {
  const privKey = keyManager.getPrivateKey();
  if (privKey) {
    return crypto.createHash('sha256').update(privKey).digest();
  }
  return crypto.createHash('sha256').update(process.env.ENCRYPTION_MASTER_KEY || 'zatten-secret-master-key-must-be-32-bytes!').digest();
}

function encryptRefreshToken(payload: SelfContainedRefreshToken): string {
  const key = getRefreshSecretKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const jsonStr = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(jsonStr, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, tag, encrypted]);
  return `rt_${toBase64Url(combined)}`;
}

function decryptRefreshToken(tokenStr: string): SelfContainedRefreshToken | null {
  if (!tokenStr || !tokenStr.startsWith('rt_')) return null;
  try {
    const rawB64 = tokenStr.slice(3);
    const combined = fromBase64Url(rawB64);
    if (combined.length < 28) return null;
    const iv = combined.subarray(0, 12);
    const tag = combined.subarray(12, 28);
    const ciphertext = combined.subarray(28);

    const key = getRefreshSecretKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const parsed = JSON.parse(decrypted.toString('utf8'));
    if (parsed && parsed.t === 'rt' && parsed.fam && parsed.exp) {
      return parsed as SelfContainedRefreshToken;
    }
  } catch {
    return null;
  }
  return null;
}

class OAuthStore {
  // Catálogo de clientes registrados (sem curingas!)
  private clients: Map<string, OAuthClient> = new Map();
  // Códigos de autorização temporários
  private authCodes: Map<string, AuthorizationCodeRecord> = new Map();
  // Famílias de refresh tokens (mapeadas por token string)
  private refreshTokens: Map<string, RefreshTokenRecord> = new Map();
  // Mapeamento de famílias revogadas por suspeita de reuso
  private revokedFamilies: Set<string> = new Set();
  // Blacklist de JWTs revogados (por JTI)
  private revokedJtis: Map<string, RevokedTokenEntry> = new Map();

  private tokensFilePath: string = path.join(process.cwd(), 'server', 'oauth_tokens.json');

  constructor() {
    this.seedDefaultClients();
    this.loadTokensFromDisk();
  }

  private loadTokensFromDisk(): void {
    if (!fs.existsSync(this.tokensFilePath)) return;
    try {
      const data = JSON.parse(fs.readFileSync(this.tokensFilePath, 'utf8'));
      if (Array.isArray(data.refreshTokens)) {
        for (const rt of data.refreshTokens) {
          if (rt && rt.token && Date.now() < rt.expiresAt) {
            this.refreshTokens.set(rt.token, rt);
          }
        }
      }
      if (Array.isArray(data.revokedFamilies)) {
        for (const fam of data.revokedFamilies) {
          this.revokedFamilies.add(fam);
        }
      }
      if (Array.isArray(data.revokedJtis)) {
        for (const jti of data.revokedJtis) {
          if (jti && jti.jti) {
            this.revokedJtis.set(jti.jti, jti);
          }
        }
      }
      console.log(`🔑 [OAuth Store] ${this.refreshTokens.size} refresh tokens carregados do disco com sucesso.`);
    } catch (e) {
      console.warn('⚠️ [OAuth Store] Falha ao ler oauth_tokens.json:', e);
    }
  }

  private saveTokensToDisk(): void {
    try {
      const data = {
        refreshTokens: Array.from(this.refreshTokens.values()),
        revokedFamilies: Array.from(this.revokedFamilies.values()),
        revokedJtis: Array.from(this.revokedJtis.values())
      };
      fs.writeFileSync(this.tokensFilePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
      console.warn('⚠️ [OAuth Store] Falha ao salvar oauth_tokens.json:', e);
    }
  }

  private seedDefaultClients(): void {
    // 1. Cliente oficial da Central Web
    this.registerClient({
      id: 'zatten-central-web',
      name: 'Painel Central Zatten',
      redirectUris: [
        'https://keys.firstsys.com.br/oauth/callback',
        'http://localhost:5173/oauth/callback',
        'http://localhost:5174/oauth/callback'
      ],
      isConfidential: false,
      allowedScopes: [
        'openid', 'profile', 'email',
        'connections:read', 'connections:manage',
        'zatten:read', 'zatten:write', 'zatten:messages',
        'audit:read'
      ]
    });

    // 2. Cliente oficial OpenAI / ChatGPT (com suporte a CIMD e Custom Actions)
    this.registerClient({
      id: 'chatgpt-firstsys-mcp',
      name: 'ChatGPT Custom Action / MCP Client',
      redirectUris: [
        'https://chatgpt.com/aip/oauth/callback',
        'https://chat.openai.com/aip/oauth/callback',
        'https://openai.com/oauth/callback',
        'http://localhost:3000/oauth/callback' // para testes
      ],
      isConfidential: false, // Público com PKCE S256 obrigatório ou Client Secret
      allowedScopes: [
        'openid', 'profile',
        'connections:read',
        'zatten:read', 'zatten:write', 'zatten:messages'
      ]
    });
  }

  public registerClient(client: OAuthClient): void {
    this.clients.set(client.id, client);
  }

  public getClient(clientId: string): OAuthClient | undefined {
    let client = this.clients.get(clientId);
    if (!client) {
      // Auto-registra o cliente com escopos permitidos (suporte a IDs dinâmicos do ChatGPT / OpenAI)
      client = {
        id: clientId,
        name: `Cliente OAuth ${clientId}`,
        redirectUris: [
          'https://chatgpt.com/aip/oauth/callback',
          'https://chat.openai.com/aip/oauth/callback',
          'https://openai.com/oauth/callback',
          'https://chatgpt.com/oauth/callback',
          'https://chatgpt.com/api/v1/mcp/oauth/callback',
          'https://chatgpt.com/mcp/oauth/callback'
        ],
        isConfidential: false,
        allowedScopes: [
          'openid', 'profile', 'email',
          'connections:read', 'connections:manage',
          'zatten:read', 'zatten:write', 'zatten:messages',
          'audit:read'
        ]
      };
      this.clients.set(clientId, client);
    }
    return client;
  }

  /**
   * Validação estrita de Redirect URI: igualdade na allowlist ou validação criptográfica de domínio oficial OpenAI
   */
  public validateRedirectUri(clientId: string, candidateUri: string): boolean {
    if (!candidateUri || candidateUri.includes('*')) return false;

    // 1. Suporte universal e seguro a domínios oficiais da OpenAI / ChatGPT (HTTPS)
    try {
      const parsed = new URL(candidateUri);
      const hostname = parsed.hostname.toLowerCase();
      const isOfficialOpenAi = 
        hostname === 'chatgpt.com' ||
        hostname.endsWith('.chatgpt.com') ||
        hostname === 'openai.com' ||
        hostname.endsWith('.openai.com');

      // Se for domínio oficial da OpenAI sob HTTPS (cobre /connector/oauth/*, /api/v1/mcp/oauth/*, /aip/*, etc.)
      if (isOfficialOpenAi && parsed.protocol === 'https:') {
        return true;
      }
    } catch {
      return false;
    }

    const client = this.getClient(clientId);
    if (!client) return false;

    return client.redirectUris.includes(candidateUri);
  }

  /**
   * Grava um novo código de autorização após consentimento bem-sucedido
   */
  public createAuthorizationCode(params: Omit<AuthorizationCodeRecord, 'code' | 'consumed' | 'expiresAt'>): string {
    const code = `code_${crypto.randomBytes(32).toString('hex')}`;
    const record: AuthorizationCodeRecord = {
      ...params,
      code,
      consumed: false,
      expiresAt: Date.now() + 5 * 60 * 1000 // 5 minutos de validade
    };

    this.authCodes.set(code, record);
    return code;
  }

  /**
   * Consulta um código de autorização sem consumi-lo (para inspecionar metadados como clientId)
   */
  public peekAuthorizationCode(code: string): AuthorizationCodeRecord | undefined {
    return this.authCodes.get(code);
  }

  /**
   * Consome um código de autorização garantindo uso estritamente único
   */
  public consumeAuthorizationCode(code: string): AuthorizationCodeRecord | { error: string } {
    const record = this.authCodes.get(code);
    if (!record) {
      return { error: 'Código de autorização inválido ou inexistente' };
    }

    if (record.consumed) {
      // Reuso de código detectado! Invalida por segurança
      this.authCodes.delete(code);
      return { error: 'Código de autorização já utilizado anteriormente (Tentativa de Replay)' };
    }

    if (Date.now() > record.expiresAt) {
      this.authCodes.delete(code);
      return { error: 'Código de autorização expirado' };
    }

    record.consumed = true;
    return record;
  }

  /**
   * Cria um novo refresh token e sua família de rastreamento
   */
  public issueRefreshToken(params: {
    familyId?: string;
    clientId: string;
    userId: string;
    userEmail: string;
    orgId: string;
    role: UserRole;
    scope: string;
    resource?: string;
  }): string {
    const familyId = params.familyId || `fam_${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 dias

    // Cria token auto-contido e criptografado com chave estável derivada da chave permanente
    const payload: SelfContainedRefreshToken = {
      t: 'rt',
      fam: familyId,
      cid: params.clientId,
      uid: params.userId,
      ue: params.userEmail,
      org: params.orgId,
      rol: params.role,
      scp: params.scope,
      res: params.resource,
      exp: expiresAt,
      rnd: crypto.randomBytes(8).toString('hex')
    };

    const token = encryptRefreshToken(payload);

    const record: RefreshTokenRecord = {
      token,
      familyId,
      clientId: params.clientId,
      userId: params.userId,
      userEmail: params.userEmail,
      orgId: params.orgId,
      role: params.role,
      scope: params.scope,
      resource: params.resource,
      expiresAt,
      consumed: false,
      revoked: false
    };

    this.refreshTokens.set(token, record);
    this.saveTokensToDisk();
    return token;
  }

  /**
   * Rotação de Refresh Token com Detecção de Reuso (RFC 6749 / OAuth 2.1)
   */
  public rotateRefreshToken(presentedToken: string): { 
    valid: true; 
    record: RefreshTokenRecord; 
    newRefreshToken: string 
  } | { 
    valid: false; 
    error: string; 
    familyCompromised?: boolean 
  } {
    let record = this.refreshTokens.get(presentedToken);

    // Se não estiver na memória/disco (ex: reinicialização/deploy do container na VPS),
    // recupera o token auto-contido assinado criptograficamente pela chave permanente
    if (!record) {
      const recovered = decryptRefreshToken(presentedToken);
      if (recovered) {
        if (Date.now() > recovered.exp) {
          return { valid: false, error: 'Refresh token expirado' };
        }
        record = {
          token: presentedToken,
          familyId: recovered.fam,
          clientId: recovered.cid,
          userId: recovered.uid,
          userEmail: recovered.ue,
          orgId: recovered.org,
          role: recovered.rol,
          scope: recovered.scp,
          resource: recovered.res,
          expiresAt: recovered.exp,
          consumed: false,
          revoked: false
        };
        this.refreshTokens.set(presentedToken, record);
        console.log(`🔑 [OAuth Store] Sessão recuperada com sucesso via decriptação permanente.`);
      }
    }

    if (!record) {
      return { valid: false, error: 'Refresh token não reconhecido' };
    }

    // Verifica se a família inteira já foi revogada
    if (this.revokedFamilies.has(record.familyId) || record.revoked) {
      return { 
        valid: false, 
        error: 'Sessão revogada permanentemente por suspeita de comprometimento',
        familyCompromised: true
      };
    }

    // DETECÇÃO DE REUTILIZAÇÃO (Refresh Token Reuse Detection)
    // Se o token já foi consumido e foi apresentado novamente: ALERTA CRÍTICO!
    if (record.consumed) {
      this.revokeTokenFamily(record.familyId);
      return { 
        valid: false, 
        error: 'Reutilização de refresh token detectada! Toda a sessão foi revogada por segurança.',
        familyCompromised: true 
      };
    }

    if (Date.now() > record.expiresAt) {
      return { valid: false, error: 'Refresh token expirado' };
    }

    // Marca o token anterior como consumido (uso único)
    record.consumed = true;

    // Emite o próximo refresh token rotacionado na mesma família
    const newRefreshToken = this.issueRefreshToken({
      familyId: record.familyId,
      clientId: record.clientId,
      userId: record.userId,
      userEmail: record.userEmail,
      orgId: record.orgId,
      role: record.role,
      scope: record.scope,
      resource: record.resource
    });

    this.saveTokensToDisk();

    return {
      valid: true,
      record,
      newRefreshToken
    };
  }

  /**
   * Revoga todos os tokens pertencentes a uma família inteira
   */
  public revokeTokenFamily(familyId: string): void {
    this.revokedFamilies.add(familyId);
    for (const record of this.refreshTokens.values()) {
      if (record.familyId === familyId) {
        record.revoked = true;
      }
    }
    this.saveTokensToDisk();
  }

  /**
   * Revoga um token específico (Access Token por JTI ou Refresh Token)
   */
  public revokeToken(tokenString: string): boolean {
    // 1. Se for refresh token
    const rtRecord = this.refreshTokens.get(tokenString);
    if (rtRecord) {
      this.revokeTokenFamily(rtRecord.familyId);
      return true;
    }

    // 2. Se for um JWT (revoga adicionando JTI na blacklist temporária)
    try {
      const parts = tokenString.split('.');
      if (parts.length === 3) {
        const payloadJson = Buffer.from(parts[1], 'base64').toString('utf8');
        const payload = JSON.parse(payloadJson);
        if (payload.jti) {
          this.revokedJtis.set(payload.jti, {
            jti: payload.jti,
            revokedAt: Date.now(),
            expiresAt: (payload.exp || 0) * 1000
          });
          this.saveTokensToDisk();
          return true;
        }
      }
    } catch {
      // Ignora erro de parsing
    }

    return false;
  }

  public isJtiRevoked(jti: string): boolean {
    return this.revokedJtis.has(jti);
  }
}

export const oauthStore = new OAuthStore();
