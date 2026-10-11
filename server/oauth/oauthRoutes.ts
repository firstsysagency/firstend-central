/**
 * ROTAS E ENDPOINTS OAUTH 2.1 E OPENID CONNECT
 * Central Privada de Conexões Zatten — Firstsys
 * Implementação RFC 6749, RFC 7636 (PKCE S256), RFC 8414 e RFC 7009
 */

import express, { Router, type Request, type Response } from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { 
  AuthorizationRequestSchema, 
  TokenRequestSchema, 
  RevocationRequestSchema,
  OAUTH_SCOPES,
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

// Recupera o usuário autenticado por sessão ativa (cookie HttpOnly zatten_session ou Bearer token)
function getAuthenticatedUserFromRequest(req: Request): any | null {
  if ((req as any).user) return (req as any).user;

  try {
    const authHeader = req.headers.authorization;
    const cookieHeader = req.headers.cookie;
    let token: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else if (cookieHeader) {
      const match = cookieHeader.split(';').find(c => c.trim().startsWith('zatten_session='));
      if (match) token = match.split('=')[1].trim();
    }

    if (!token) return null;

    const jwtSecret = process.env.JWT_SECRET || 'super-secret-jwt-key';
    const decoded: any = jwt.verify(token, jwtSecret);
    const dbPath = path.join(process.cwd(), 'server', 'db.json');
    if (fs.existsSync(dbPath)) {
      const db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
      const user = db.users?.find((u: any) => u.id === decoded.id || u.email === decoded.email);
      if (user && user.status !== 'suspended') {
        return user;
      }
    }
  } catch {
    // Ignora token inválido ou expirado
  }
  return null;
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
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    scopes_supported: [...OAUTH_SCOPES],
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
    scopes_supported: [...OAUTH_SCOPES],
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
    console.log('🔑 [OAuth Authorize]', { client_id, redirect_uri });
    const isUriAllowed = oauthStore.validateRedirectUri(client_id, redirect_uri);
    if (!isUriAllowed) {
      console.warn('⚠️ [OAuth Authorize Rejeitado: Redirect URI não permitida]', { client_id, redirect_uri });
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Redirect URI não autorizada ou incompatível com a allowlist estrita do cliente.'
      });
    }

    // 2. Verificação de Sessão do Usuário
    // Obtém usuário da sessão ativa (cookie HttpOnly zatten_session ou header Bearer)
    const sessionUser = getAuthenticatedUserFromRequest(req);
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
    // 1. Suporte RFC 6749 Seção 2.3.1 (client_secret_basic via HTTP Basic Auth)
    if (req.headers.authorization && req.headers.authorization.startsWith('Basic ')) {
      try {
        const credentials = Buffer.from(req.headers.authorization.slice(6).trim(), 'base64').toString('utf8');
        const colonIdx = credentials.indexOf(':');
        if (colonIdx !== -1) {
          const clientId = decodeURIComponent(credentials.slice(0, colonIdx));
          const clientSecret = decodeURIComponent(credentials.slice(colonIdx + 1));
          if (!req.body.client_id) req.body.client_id = clientId;
          if (!req.body.client_secret) req.body.client_secret = clientSecret;
        }
      } catch (e) {
        console.warn('⚠️ [OAuth Token] Falha ao extrair Basic Auth:', e);
      }
    }

    // 2. Se client_id não foi informado no body, deduz do registro do código
    if (!req.body.client_id && req.body.code) {
      const peeked = oauthStore.peekAuthorizationCode(req.body.code);
      if (peeked) {
        req.body.client_id = peeked.clientId;
      }
    }

    console.log('🔑 [OAuth Token Request Recebido]', {
      grant_type: req.body?.grant_type,
      client_id: req.body?.client_id,
      redirect_uri: req.body?.redirect_uri,
      has_code: !!req.body?.code,
      has_code_verifier: !!req.body?.code_verifier
    });

    const parseResult = TokenRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      console.warn('⚠️ [OAuth Token Rejeitado por Schema]', parseResult.error.issues);
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
        console.warn('⚠️ [OAuth Token Rejeitado por Código]', codeRecord.error);
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: codeRecord.error
        });
      }

      // Valida client_id
      const effectiveClientId = body.client_id || codeRecord.clientId;
      if (body.client_id && codeRecord.clientId !== body.client_id) {
        console.warn('⚠️ [OAuth Token Client ID Divergente]', { codeClientId: codeRecord.clientId, bodyClientId: body.client_id });
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Código de autorização não pertence a este client_id'
        });
      }

      // Valida redirect_uri se informada
      if (body.redirect_uri && codeRecord.redirectUri !== body.redirect_uri) {
        console.warn('⚠️ [OAuth Token Redirect URI Divergente]', { codeUri: codeRecord.redirectUri, bodyUri: body.redirect_uri });
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'redirect_uri divergente da especificada na requisição de autorização'
        });
      }

      // VALIDAÇÃO PKCE S256 (Obrigatória se code_challenge tiver sido fornecido)
      if (codeRecord.codeChallenge) {
        if (!body.code_verifier) {
          console.warn('⚠️ [OAuth Token Falta code_verifier]');
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'code_verifier é obrigatório para códigos gerados com PKCE'
          });
        }

        const isPkceValid = verifyPkceChallenge(body.code_verifier, codeRecord.codeChallenge);
        if (!isPkceValid) {
          logAuditEvent({
            actor: effectiveClientId,
            action: 'oauth.pkce.failed',
            category: 'security',
            severity: 'critical',
            description: `Falha na verificação PKCE S256 para o cliente ${effectiveClientId}`,
            ipAddress: req.ip || '127.0.0.1'
          });

          console.warn('⚠️ [OAuth Token PKCE Inválido]');
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'code_verifier inválido para o code_challenge registrado'
          });
        }
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
      const expiresInSec = 3600; // 1 hora de validade

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
        client_id: effectiveClientId
      };

      const accessToken = signJwt(tokenPayload);

      // Emissão de Refresh Token com Família de Rastreamento
      const refreshToken = oauthStore.issueRefreshToken({
        clientId: effectiveClientId,
        userId: codeRecord.userId,
        userEmail: codeRecord.userEmail,
        orgId: codeRecord.orgId,
        role: codeRecord.role,
        scope: codeRecord.scope,
        resource: targetAudience
      });

      // Emissão de id_token se escopo openid estiver presente (OIDC Core 1.0)
      let idToken: string | undefined;
      if (codeRecord.scope.includes('openid')) {
        idToken = signJwt({
          iss: issuer,
          sub: codeRecord.userId,
          aud: effectiveClientId,
          exp: nowSec + 3600,
          iat: nowSec,
          email: codeRecord.userEmail,
          email_verified: true,
          nonce: codeRecord.nonce
        });
      }

      const responsePayload: OAuthTokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: expiresInSec,
        refresh_token: refreshToken,
        scope: codeRecord.scope,
        ...(idToken ? { id_token: idToken } : {})
      };

      console.log('🎉 [OAuth Token Emitido com Sucesso]', {
        client_id: effectiveClientId,
        user: codeRecord.userEmail,
        has_id_token: !!idToken
      });

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

// ==============================================================================
// 8. MANIFESTO OPENAPI 3.1.0 PARA CHATGPT ACTIONS / MCP
// ==============================================================================

const openApiHandler = (req: Request, res: Response) => {
  const issuer = getBaseIssuer(req);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json({
    openapi: '3.1.0',
    info: {
      title: 'Firstsys Zatten Central MCP API',
      description: 'API e Servidor MCP remoto para integração segura do ChatGPT com a Zatten via Firstsys OAuth 2.1.',
      version: '1.0.0'
    },
    servers: [
      {
        url: issuer,
        description: 'Servidor Principal de Produção'
      }
    ],
    paths: {
      '/mcp/tools/firstsys_get_profile': {
        post: {
          operationId: 'firstsys_get_profile',
          summary: 'Obter perfil da conta Firstsys autenticada',
          description: 'Retorna o identificador opaco permanente, organização e papéis da conta Firstsys autorizada.',
          responses: {
            '200': {
              description: 'Perfil autenticado retornado com sucesso',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      id: { type: 'string' },
                      organizationId: { type: 'string' },
                      role: { type: 'string' },
                      scope: { type: 'string' },
                      client: { type: 'string' }
                    }
                  }
                }
              }
            }
          }
        }
      },
      '/mcp/tools/zatten_list_connections': {
        post: {
          operationId: 'zatten_list_connections',
          summary: 'Listar conexões Zatten ativas',
          description: 'Lista todas as conexões Zatten ativas e operacionais autorizadas para a organização.',
          responses: {
            '200': {
              description: 'Lista de conexões ativas',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      connections: {
                        type: 'array',
                        items: {
                          type: 'object',
                          properties: {
                            id: { type: 'string' },
                            name: { type: 'string' },
                            status: { type: 'string' },
                            environment: { type: 'string' }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      '/mcp/tools/zatten_get_connection_status': {
        post: {
          operationId: 'zatten_get_connection_status',
          summary: 'Consultar status da conexão Zatten',
          description: 'Consulta o status de integridade e prontidão operacional de uma conexão Zatten específica.',
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    connectionId: { type: 'string', description: 'ID da conexão a ser consultada' }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Status da conexão retornado com sucesso',
              content: {
                'application/json': {
                  schema: { type: 'object' }
                }
              }
            }
          }
        }
      },
      '/mcp/tools/zatten_get_leads': {
        post: {
          operationId: 'zatten_get_leads',
          summary: 'Consultar leads ou Kanban no CRM Zatten',
          description: 'Consulta informações de leads no CRM Zatten. Se informado leadNumber, retorna os dados do lead específico. Se omitido, retorna a visão geral do Kanban e colunas ativas do CRM.',
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    leadNumber: { type: 'string', description: 'Número de telefone/identificador do lead (DDI+DDD+Número, ex: 5511999999999). Opcional.' },
                    connectionId: { type: 'string', description: 'ID opcional da conexão Zatten' }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Lista de leads retornada com sucesso',
              content: {
                'application/json': {
                  schema: { type: 'object' }
                }
              }
            }
          }
        }
      },
      '/mcp/tools/zatten_send_message': {
        post: {
          operationId: 'zatten_send_message',
          summary: 'Disparar mensagem para contato via Zatten',
          description: 'Dispara uma mensagem para um contato via API Zatten. AÇÃO DE ESCRITA: EXIGE CONFIRMAÇÃO DO USUÁRIO.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['recipient', 'message'],
                  properties: {
                    recipient: { type: 'string', description: 'Número do destinatário com DDI e DDD' },
                    message: { type: 'string', description: 'Texto da mensagem a ser enviada' },
                    connectionId: { type: 'string', description: 'ID da conexão Zatten específica (opcional)' }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Mensagem enviada com sucesso',
              content: {
                'application/json': {
                  schema: { type: 'object' }
                }
              }
            }
          }
        }
      },
      '/mcp/tools/zatten_update_lead': {
        post: {
          operationId: 'zatten_update_lead',
          summary: 'Atualizar lead no funil Zatten',
          description: 'Atualiza propriedades, anotações ou etapa do lead no funil Zatten.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['leadId'],
                  properties: {
                    leadId: { type: 'string', description: 'Identificador do lead' },
                    stage: { type: 'string', description: 'Nova etapa do funil' },
                    notes: { type: 'string', description: 'Anotações complementares' },
                    connectionId: { type: 'string', description: 'ID da conexão Zatten' }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Lead atualizado com sucesso',
              content: {
                'application/json': {
                  schema: { type: 'object' }
                }
              }
            }
          }
        }
      }
    },
    components: {
      securitySchemes: {
        OAuth2: {
          type: 'oauth2',
          description: 'Autenticação OAuth 2.1 Firstsys Central',
          flows: {
            authorizationCode: {
              authorizationUrl: `${issuer}/oauth/authorize`,
              tokenUrl: `${issuer}/oauth/token`,
              scopes: {
                'profile': 'Acessar dados do perfil e organização',
                'connections:read': 'Listar conexões ativas',
                'zatten:read': 'Consultar leads e dados Zatten',
                'zatten:write': 'Atualizar propriedades no CRM Zatten',
                'zatten:messages': 'Disparar mensagens via Zatten'
              }
            }
          }
        }
      }
    }
  });
};

oauthRouter.get('/openapi.json', openApiHandler);
oauthRouter.get('/mcp/openapi.json', openApiHandler);
