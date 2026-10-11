/**
 * ROTAS E ENDPOINTS OAUTH 2.1 E OPENID CONNECT
 * Central Privada de Conexões Zatten — Firstsys
 * Implementação RFC 6749, RFC 7636 (PKCE S256), RFC 8414 e RFC 7009
 */

import express, { Router, type Request, type Response } from 'express';
import crypto from 'crypto';
import { 
  AuthorizationRequestSchema, 
  TokenRequestSchema, 
  RevocationRequestSchema,
  type OAuthJwtPayload,
  type OAuthTokenResponse
} from './oauthTypes.js';
import { 
  keyManager, 
  verifyPkceChallenge, 
  signJwt, 
  verifyJwt 
} from './cryptoEngine.js';
import { oauthStore } from './oauthStore.js';
import { logAuditEvent } from '../../src/lib/audit.js';

export const oauthRouter = Router();

// Função auxiliar para determinar a base do issuer
function getBaseIssuer(req: Request): string {
  if (process.env.OAUTH_ISSUER_URL) {
    return process.env.OAUTH_ISSUER_URL;
  }
  const host = req.get('host') || 'localhost:3000';
  const protocol = req.secure || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
  return `${protocol}://${host}`;
}

// ==============================================================================
// 1. DESCOBERTA OIDC & OAUTH 2.1 (RFC 8414 & OpenID Connect Discovery)
// ==============================================================================

const openIdConfigurationHandler = (req: Request, res: Response) => {
  const issuer = getBaseIssuer(req);

  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    scopes_supported: [
      'openid', 'profile', 'email',
      'connections:read', 'connections:manage',
      'zatten:read', 'zatten:write', 'zatten:messages',
      'audit:read'
    ],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'email', 'role', 'org_id'],
    service_documentation: 'https://docs.firstsys.com.br/oauth'
  });
};

oauthRouter.get('/.well-known/openid-configuration', openIdConfigurationHandler);
oauthRouter.get('/.well-known/oauth-authorization-server', openIdConfigurationHandler);

// ==============================================================================
// 2. METADADOS DE RECURSO PROTEGIDO MCP & CHATGPT (RFC Draft Protected Resource)
// ==============================================================================

oauthRouter.get('/.well-known/oauth-protected-resource', (req: Request, res: Response) => {
  const issuer = getBaseIssuer(req);
  const mcpResourceUrl = process.env.MCP_RESOURCE_IDENTIFIER || `${issuer}/mcp`;

  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json({
    resource: mcpResourceUrl,
    authorization_servers: [issuer],
    scopes_supported: [
      'connections:read',
      'connections:manage',
      'zatten:read',
      'zatten:write',
      'zatten:messages',
      'audit:read'
    ],
    bearer_methods_supported: ['header'],
    resource_documentation: 'https://docs.firstsys.com.br/mcp'
  });
});

// ==============================================================================
// 3. CONJUNTO DE CHAVES PÚBLICAS (JWKS - RFC 7517)
// ==============================================================================

oauthRouter.get('/.well-known/jwks.json', (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'public, max-age=86400'); // 24h com suporte a rotação
  res.json(keyManager.getJwks());
});

// ==============================================================================
// 4. ENDPOINT DE AUTORIZAÇÃO (GET /oauth/authorize)
// ==============================================================================

oauthRouter.get('/oauth/authorize', (req: Request, res: Response) => {
  try {
    const parseResult = AuthorizationRequestSchema.safeParse(req.query);
    if (!parseResult.success) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: parseResult.error.issues.map(i => i.message).join('; ')
      });
    }

    const {
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
      resource,
      nonce
    } = parseResult.data;

    // 1. Validação estrita de Redirect URI (Sem curingas)
    const isUriAllowed = oauthStore.validateRedirectUri(client_id, redirect_uri);
    if (!isUriAllowed) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Redirect URI não autorizada ou incompatível com a allowlist estrita do cliente.'
      });
    }

    // 2. Verificação de Sessão do Usuário
    // Em um fluxo web real, a sessão vem de cookie HttpOnly ou token
    // Se não estiver logado, redireciona para login com return_to
    const sessionUser = (req as any).user;
    if (!sessionUser) {
      const returnUrl = encodeURIComponent(req.originalUrl);
      return res.redirect(`/login?return_to=${returnUrl}`);
    }

    // 3. Exigência de MFA Obrigatório para Administradores (Checklist de Segurança)
    const isAdmin = sessionUser.role === 'owner' || sessionUser.role === 'admin';
    if (isAdmin && !sessionUser.twoFactorEnabled) {
      return res.status(403).json({
        error: 'mfa_required',
        error_description: 'Administradores e Proprietários devem ter Autenticação em Duas Etapas (MFA) ativada para autorizar aplicações.'
      });
    }

    // 4. Criação do Código de Autorização Temporário (5 minutos, uso único)
    const code = oauthStore.createAuthorizationCode({
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      userId: sessionUser.id || 'usr_default',
      userEmail: sessionUser.email || 'contato@firstsys.com.br',
      orgId: sessionUser.orgId || 'org_firstsys_prod',
      role: sessionUser.role || 'owner',
      scope: scope.join(' '),
      resource,
      nonce
    });

    logAuditEvent({
      actor: sessionUser.email || client_id,
      action: 'oauth.consent.granted',
      category: 'auth',
      severity: 'info',
      description: `Consentimento OAuth 2.1 concedido para o cliente ${client_id}`,
      ipAddress: req.ip || '127.0.0.1'
    });

    // 5. Redirecionamento seguro de volta ao cliente com code e state
    const targetUrl = new URL(redirect_uri);
    targetUrl.searchParams.set('code', code);
    targetUrl.searchParams.set('state', state);

    return res.redirect(targetUrl.toString());
  } catch (err: unknown) {
    console.error('[OAuth Authorize] Erro:', err);
    return res.status(500).json({ error: 'server_error', error_description: 'Falha interna ao processar autorização' });
  }
});

// ==============================================================================
// 5. ENDPOINT DE TOKEN (POST /oauth/token)
// ==============================================================================

oauthRouter.post('/oauth/token', express.urlencoded({ extended: true }), express.json(), (req: Request, res: Response) => {
  try {
    const parseResult = TokenRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: parseResult.error.issues.map(i => i.message).join('; ')
      });
    }

    const issuer = getBaseIssuer(req);
    const body = parseResult.data;

    // FLUXO A: GRANT TYPE = AUTHORIZATION_CODE
    if (body.grant_type === 'authorization_code') {
      const codeRecord = oauthStore.consumeAuthorizationCode(body.code);
      if ('error' in codeRecord) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: codeRecord.error
        });
      }

      // Valida client_id
      if (codeRecord.clientId !== body.client_id) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Código de autorização não pertence a este client_id'
        });
      }

      // Valida redirect_uri exata
      if (codeRecord.redirectUri !== body.redirect_uri) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'redirect_uri divergente da especificada na requisição de autorização'
        });
      }

      // VALIDAÇÃO PKCE S256 OBRIGATÓRIA
      const isPkceValid = verifyPkceChallenge(body.code_verifier, codeRecord.codeChallenge);
      if (!isPkceValid) {
        logAuditEvent({
          actor: body.client_id,
          action: 'oauth.pkce.failed',
          category: 'security',
          severity: 'critical',
          description: `Falha na verificação PKCE S256 para o cliente ${body.client_id}`,
          ipAddress: req.ip || '127.0.0.1'
        });

        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'code_verifier inválido para o code_challenge registrado'
        });
      }

      // Validação de Parâmetro Resource (Audiência MCP)
      if (body.resource && codeRecord.resource && body.resource !== codeRecord.resource) {
        return res.status(400).json({
          error: 'invalid_target',
          error_description: 'O parâmetro resource especificado diverge do autorizado no consentimento'
        });
      }

      const targetAudience = body.resource || codeRecord.resource || `${issuer}/mcp`;
      const jti = `jti_${crypto.randomBytes(16).toString('hex')}`;
      const nowSec = Math.floor(Date.now() / 1000);
      const expiresInSec = 900; // 15 minutos (Access Token curto)

      // Emissão de Access Token JWT assinado assimetricamente (RS256)
      const tokenPayload: OAuthJwtPayload = {
        iss: issuer,
        sub: codeRecord.userId,
        aud: targetAudience,
        exp: nowSec + expiresInSec,
        nbf: nowSec - 5,
        iat: nowSec,
        jti,
        org_id: codeRecord.orgId,
        role: codeRecord.role,
        scope: codeRecord.scope,
        client_id: codeRecord.clientId
      };

      const accessToken = signJwt(tokenPayload);

      // Emissão de Refresh Token com Família de Rastreamento
      const refreshToken = oauthStore.issueRefreshToken({
        clientId: codeRecord.clientId,
        userId: codeRecord.userId,
        userEmail: codeRecord.userEmail,
        orgId: codeRecord.orgId,
        role: codeRecord.role,
        scope: codeRecord.scope,
        resource: targetAudience
      });

      const responsePayload: OAuthTokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: expiresInSec,
        refresh_token: refreshToken,
        scope: codeRecord.scope
      };

      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      return res.json(responsePayload);
    }

    // FLUXO B: GRANT TYPE = REFRESH_TOKEN
    if (body.grant_type === 'refresh_token') {
      const rotationResult = oauthStore.rotateRefreshToken(body.refresh_token);

      if (!rotationResult.valid) {
        logAuditEvent({
          actor: body.client_id,
          action: 'oauth.token_reuse.detected',
          category: 'security',
          severity: 'critical',
          description: `Tentativa de reuso de refresh token detectada! Erro: ${rotationResult.error}`,
          ipAddress: req.ip || '127.0.0.1'
        });

        return res.status(400).json({
          error: 'invalid_grant',
          error_description: rotationResult.error
        });
      }

      const { record, newRefreshToken } = rotationResult;

      // Validação de client_id
      if (record.clientId !== body.client_id) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Refresh token não pertence a este client_id'
        });
      }

      const targetAudience = body.resource || record.resource || `${issuer}/mcp`;
      const jti = `jti_${crypto.randomBytes(16).toString('hex')}`;
      const nowSec = Math.floor(Date.now() / 1000);
      const expiresInSec = 900; // 15 minutos

      const tokenPayload: OAuthJwtPayload = {
        iss: issuer,
        sub: record.userId,
        aud: targetAudience,
        exp: nowSec + expiresInSec,
        nbf: nowSec - 5,
        iat: nowSec,
        jti,
        org_id: record.orgId,
        role: record.role,
        scope: record.scope,
        client_id: record.clientId,
        token_family_id: record.familyId
      };

      const accessToken = signJwt(tokenPayload);

      const responsePayload: OAuthTokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: expiresInSec,
        refresh_token: newRefreshToken,
        scope: record.scope
      };

      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      return res.json(responsePayload);
    }

    return res.status(400).json({ error: 'unsupported_grant_type' });
  } catch (err: unknown) {
    console.error('[OAuth Token] Erro:', err);
    return res.status(500).json({ error: 'server_error', error_description: 'Falha ao processar troca de token' });
  }
});

// ==============================================================================
// 6. ENDPOINT DE REVOGAÇÃO DE TOKEN (POST /oauth/revoke - RFC 7009)
// ==============================================================================

oauthRouter.post('/oauth/revoke', express.urlencoded({ extended: true }), express.json(), (req: Request, res: Response) => {
  try {
    const parseResult = RevocationRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: parseResult.error.issues.map(i => i.message).join('; ')
      });
    }

    const { token, client_id } = parseResult.data;

    // RFC 7009: Revoga o token (se for refresh token ou JWT)
    oauthStore.revokeToken(token);

    logAuditEvent({
      actor: client_id,
      action: 'oauth.token.revoked',
      category: 'auth',
      severity: 'info',
      description: `Token revogado formalmente pelo cliente ${client_id}`,
      ipAddress: req.ip || '127.0.0.1'
    });

    // Conforme a RFC 7009, o servidor DEVE responder 200 OK mesmo se o token não existir
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({ success: true, message: 'Token revogado com sucesso' });
  } catch (err: unknown) {
    console.error('[OAuth Revoke] Erro:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// ==============================================================================
// 7. ENDPOINT DE USERINFO (GET /oauth/userinfo - OpenID Connect)
// ==============================================================================

oauthRouter.get('/oauth/userinfo', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    return res.status(401).json({ error: 'unauthorized', error_description: 'Cabeçalho Authorization ausente' });
  }

  const token = authHeader.split(' ')[1];
  const verifyResult = verifyJwt(token);

  if (!verifyResult.valid || !verifyResult.payload) {
    res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    return res.status(401).json({ error: 'invalid_token', error_description: verifyResult.error });
  }

  const payload = verifyResult.payload;

  res.setHeader('Cache-Control', 'no-store');
  return res.json({
    sub: payload.sub,
    email: `${payload.sub}@firstsys.com.br`,
    role: payload.role,
    org_id: payload.org_id,
    email_verified: true
  });
});
