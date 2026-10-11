/**
 * MOTOR CRIPTOGRÁFICO DE ALTA SEGURANÇA PARA OAUTH 2.1 E OPENID CONNECT
 * Assinatura Assimétrica (RS256), Exportação JWKS, PKCE S256 e AES-256-GCM
 * Central Privada de Conexões Zatten — Firstsys
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { OAuthJwtPayload } from './oauthTypes.js';

export interface JwkPublicKey {
  kty: string;
  n: string;
  e: string;
  alg: string;
  use: string;
  kid: string;
}

export interface JwksResponse {
  keys: JwkPublicKey[];
}

const KEYS_DIR = path.join(process.cwd(), 'server', '.keys');

/**
 * Garante a existência do par de chaves assimétricas RSA-2048 para assinatura de tokens.
 * Em produção na VPS, as chaves são carregadas ou persistidas em pasta protegida (0700).
 */
class AsymmetricKeyManager {
  private activeKid: string = 'firstsys-key-v1';
  private privateKeyPem: string = '';
  private publicKeyPem: string = '';
  private jwkPublic: JwkPublicKey | null = null;

  constructor() {
    this.initKeys();
  }

  private initKeys(): void {
    const persistentJsonPath = path.join(process.cwd(), 'server', 'oauth', 'oauth_rsa_persistent.json');

    // 1. Prioridade Máxima: carrega par de chaves RSA permanente para estabilidade absoluta entre deploys
    if (fs.existsSync(persistentJsonPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(persistentJsonPath, 'utf8'));
        if (data.privateKeyPem && data.publicKeyPem) {
          this.privateKeyPem = data.privateKeyPem;
          this.publicKeyPem = data.publicKeyPem;
          this.activeKid = data.activeKid || 'firstsys-central-key-2026';

          const keyObject = crypto.createPublicKey(this.publicKeyPem);
          const exportedJwk = keyObject.export({ format: 'jwk' });

          this.jwkPublic = {
            kty: exportedJwk.kty || 'RSA',
            n: exportedJwk.n || '',
            e: exportedJwk.e || '',
            alg: 'RS256',
            use: 'sig',
            kid: this.activeKid
          };
          return;
        }
      } catch (e) {
        console.warn('⚠️ [OAuth Keys] Falha ao carregar oauth_rsa_persistent.json:', e);
      }
    }

    if (!fs.existsSync(KEYS_DIR)) {
      fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
    }

    const privPath = path.join(KEYS_DIR, 'oauth_rsa.key');
    const pubPath = path.join(KEYS_DIR, 'oauth_rsa.pub');
    const kidPath = path.join(KEYS_DIR, 'active_kid.txt');

    if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
      this.privateKeyPem = fs.readFileSync(privPath, 'utf8');
      this.publicKeyPem = fs.readFileSync(pubPath, 'utf8');
      if (fs.existsSync(kidPath)) {
        this.activeKid = fs.readFileSync(kidPath, 'utf8').trim();
      }
    } else {
      // Gera par de chaves RSA 2048 de alta entropia
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });

      this.privateKeyPem = privateKey;
      this.publicKeyPem = publicKey;
      this.activeKid = `firstsys-key-${Date.now()}`;

      fs.writeFileSync(privPath, this.privateKeyPem, { mode: 0o600 });
      fs.writeFileSync(pubPath, this.publicKeyPem, { mode: 0o644 });
      fs.writeFileSync(kidPath, this.activeKid, { mode: 0o644 });
    }

    // Converte a chave pública para formato JWK nativo RFC 7517
    const keyObject = crypto.createPublicKey(this.publicKeyPem);
    const exportedJwk = keyObject.export({ format: 'jwk' });

    this.jwkPublic = {
      kty: exportedJwk.kty || 'RSA',
      n: exportedJwk.n || '',
      e: exportedJwk.e || '',
      alg: 'RS256',
      use: 'sig',
      kid: this.activeKid
    };
  }

  public getActiveKid(): string {
    return this.activeKid;
  }

  public getPrivateKey(): string {
    return this.privateKeyPem;
  }

  public getPublicKey(): string {
    return this.publicKeyPem;
  }

  public getJwks(): JwksResponse {
    if (!this.jwkPublic) {
      throw new Error('Chaves públicas ainda não inicializadas');
    }
    return { keys: [this.jwkPublic] };
  }
}

export const keyManager = new AsymmetricKeyManager();

// ==============================================================================
// FUNÇÕES AUXILIARES DE CODIFICAÇÃO BASE64URL (RFC 4648)
// ==============================================================================

export function toBase64Url(buffer: Buffer): string {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function fromBase64Url(base64url: string): Buffer {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

// ==============================================================================
// VALIDAÇÃO CRIPTOGRÁFICA DE PKCE S256 (RFC 7636)
// ==============================================================================

/**
 * Valida o code_verifier fornecido pelo cliente contra o code_challenge registrado.
 * Cálculo obrigatório: BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge
 */
export function verifyPkceChallenge(codeVerifier: string, codeChallenge: string): boolean {
  if (!codeVerifier || !codeChallenge) return false;
  if (codeVerifier.length < 43 || codeVerifier.length > 128) return false;

  const hash = crypto.createHash('sha256').update(codeVerifier, 'ascii').digest();
  const calculatedChallenge = toBase64Url(hash);

  const calcBuf = Buffer.from(calculatedChallenge, 'utf8');
  const expBuf = Buffer.from(codeChallenge, 'utf8');

  if (calcBuf.length !== expBuf.length) return false;
  return crypto.timingSafeEqual(calcBuf, expBuf);
}

// ==============================================================================
// ASSINATURA E VERIFICAÇÃO ASSIMÉTRICA DE JWT (RS256)
// ==============================================================================

export function signJwt(payload: OAuthJwtPayload): string {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: keyManager.getActiveKid()
  };

  const encodedHeader = toBase64Url(Buffer.from(JSON.stringify(header)));
  const encodedPayload = toBase64Url(Buffer.from(JSON.stringify(payload)));
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(dataToSign);
  const signature = signer.sign(keyManager.getPrivateKey());
  const encodedSignature = toBase64Url(signature);

  return `${dataToSign}.${encodedSignature}`;
}

export function verifyJwt(token: string): { valid: boolean; payload?: OAuthJwtPayload; error?: string } {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Token JWT malformado' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    const dataToVerify = `${headerB64}.${payloadB64}`;
    const signature = fromBase64Url(signatureB64);

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(dataToVerify);
    const isSignatureValid = verifier.verify(keyManager.getPublicKey(), signature);

    if (!isSignatureValid) {
      return { valid: false, error: 'Assinatura assimétrica inválida' };
    }

    const payloadJson = fromBase64Url(payloadB64).toString('utf8');
    const payload = JSON.parse(payloadJson) as OAuthJwtPayload;

    const nowSeconds = Math.floor(Date.now() / 1000);

    // Valida expiração com 30s de margem para clock drift
    if (payload.exp && nowSeconds > payload.exp + 30) {
      return { valid: false, error: 'Token expirado' };
    }

    // Valida Not Before (nbf)
    if (payload.nbf && nowSeconds < payload.nbf - 30) {
      return { valid: false, error: 'Token ainda não está ativo (nbf)' };
    }

    return { valid: true, payload };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Erro ao validar token JWT';
    return { valid: false, error: message };
  }
}

// ==============================================================================
// CRIPTOGRAFIA AUTENTICADA AES-256-GCM PARA SEGREDOS EM REPOUSO
// ==============================================================================

const MASTER_ENCRYPTION_KEY = process.env.ENCRYPTION_MASTER_KEY || 'zatten-secret-master-key-must-be-32-bytes!';
// Garante 32 bytes exatos para AES-256
const DERIVED_AES_KEY = crypto.createHash('sha256').update(MASTER_ENCRYPTION_KEY).digest();

export interface EncryptedSecretData {
  ciphertext: string; // Base64
  iv: string;         // Base64 (12 bytes)
  tag: string;        // Base64 (16 bytes)
  version: number;
}

export function encryptSecret(plainText: string): EncryptedSecretData {
  const iv = crypto.randomBytes(12); // Padrão NIST para GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', DERIVED_AES_KEY, iv);
  
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    version: 1
  };
}

export function decryptSecret(data: EncryptedSecretData): string {
  const iv = Buffer.from(data.iv, 'base64');
  const tag = Buffer.from(data.tag, 'base64');
  const ciphertext = Buffer.from(data.ciphertext, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', DERIVED_AES_KEY, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

/**
 * Gera identificadores opacos seguros e não previsíveis (ex: connectionId, auth code)
 */
export function generateOpaqueId(prefix: string = 'id', byteLength: number = 24): string {
  const random = crypto.randomBytes(byteLength).toString('hex');
  return `${prefix}_${random}`;
}
