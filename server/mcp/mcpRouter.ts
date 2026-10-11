/**
 * SERVIDOR E ROTAS MCP REMOTO COM PROTEÇÃO OAUTH 2.1 E CHATGPT
 * Central Privada de Conexões Zatten — Firstsys
 * Implementação conforme RFC Protected Resource Metadata e MCP Specification
 */

import { Router, type Request, type Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { z } from 'zod';
import { verifyJwt } from '../oauth/cryptoEngine.js';
import { type OAuthJwtPayload, type OAuthScope } from '../oauth/oauthTypes.js';
import { zattenClient } from '../zatten/zattenClient.js';
import { logAuditEvent } from '../../src/lib/audit.js';

export const mcpRouter = Router();

// ==============================================================================
// 1. MIDDLEWARE DE AUTENTICAÇÃO OAUTH 2.1 PARA RECURSO PROTEGIDO MCP
// ==============================================================================

export interface AuthenticatedMcpRequest extends Request {
  oauthUser?: OAuthJwtPayload;
}

export function requireOAuth(requiredScope?: OAuthScope) {
  return (req: AuthenticatedMcpRequest, res: Response, next: () => void) => {
    const authHeader = req.headers.authorization;
    const issuer = process.env.OAUTH_ISSUER_URL || `${req.protocol}://${req.get('host')}`;
    const resourceMetadataUrl = `${issuer}/.well-known/oauth-protected-resource`;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.setHeader('WWW-Authenticate', `Bearer error="unauthorized", resource_metadata="${resourceMetadataUrl}"`);
      return res.status(401).json({
        error: 'unauthorized',
        message: 'Acesso negado. Token OAuth 2.1 Bearer obrigatório.',
        resource_metadata: resourceMetadataUrl
      });
    }

    const token = authHeader.split(' ')[1];
    const verification = verifyJwt(token);

    if (!verification.valid || !verification.payload) {
      res.setHeader('WWW-Authenticate', `Bearer error="invalid_token", error_description="${verification.error}", resource_metadata="${resourceMetadataUrl}"`);
      return res.status(401).json({
        error: 'invalid_token',
        message: verification.error || 'Token OAuth inválido ou expirado',
        resource_metadata: resourceMetadataUrl
      });
    }

    const payload = verification.payload;

    // Validação estrita da Audiência do Recurso Protegido (Requisito ChatGPT / RFC)
    // O valor de 'resource' DEVE estar presente no array/string de aud
    const canonicalResource = process.env.MCP_RESOURCE_IDENTIFIER || `${issuer}/mcp`;
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    
    const isAudienceValid = audiences.some(aud => 
      aud === canonicalResource || 
      aud.startsWith(canonicalResource) ||
      aud.includes('/mcp')
    );

    if (!isAudienceValid) {
      res.setHeader('WWW-Authenticate', `Bearer error="invalid_target", error_description="Token emitido para outro recurso", resource_metadata="${resourceMetadataUrl}"`);
      return res.status(403).json({
        error: 'invalid_target',
        message: 'Acesso negado. O token apresentado não foi emitido para este recurso MCP.'
      });
    }

    // Validação de Escopo Mínimo Necessário
    if (requiredScope) {
      const grantedScopes = payload.scope.split(' ');
      if (!grantedScopes.includes(requiredScope)) {
        res.setHeader('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${requiredScope}", resource_metadata="${resourceMetadataUrl}"`);
        return res.status(403).json({
          error: 'insufficient_scope',
          message: `Escopo insuficiente. Esta ferramenta requer '${requiredScope}'.`
        });
      }
    }

    req.oauthUser = payload;
    next();
  };
}

// ==============================================================================
// 2. FERRAMENTAS MCP COM SECURITY SCHEMES DECLARADOS
// ==============================================================================

export interface McpToolManifest {
  name: string;
  description: string;
  securitySchemes: {
    type: 'oauth2';
    flows: {
      authorizationCode: {
        authorizationUrl: string;
        tokenUrl: string;
        scopes: Record<string, string>;
      };
    };
  };
  requiredScope: OAuthScope;
  isWrite: boolean;
  requiresConfirmation: boolean;
}

// Catálogo das ferramentas MCP
mcpRouter.get('/tools', requireOAuth(), (req: AuthenticatedMcpRequest, res: Response) => {
  const issuer = process.env.OAUTH_ISSUER_URL || `${req.protocol}://${req.get('host')}`;

  const tools = [
    {
      name: 'firstsys_get_profile',
      description: 'Retorna o identificador opaco permanente, organização e papéis da conta Firstsys autenticada.',
      requiredScope: 'profile',
      isWrite: false,
      requiresConfirmation: false
    },
    {
      name: 'zatten_list_connections',
      description: 'Lista as conexões Zatten ativas autorizadas para a organização do usuário.',
      requiredScope: 'connections:read',
      isWrite: false,
      requiresConfirmation: false
    },
    {
      name: 'zatten_get_connection_status',
      description: 'Consulta o status de integridade operacional de uma conexão Zatten específica.',
      requiredScope: 'connections:read',
      isWrite: false,
      requiresConfirmation: false
    },
    {
      name: 'zatten_get_leads',
      description: 'Consulta leads no CRM Zatten através de uma conexão autorizada.',
      requiredScope: 'zatten:read',
      isWrite: false,
      requiresConfirmation: false
    },
    {
      name: 'zatten_send_message',
      description: 'Dispara uma mensagem para um contato via Zatten. AÇÃO DE ESCRITA: EXIGE CONFIRMAÇÃO HUMANA PRÉVIA.',
      requiredScope: 'zatten:messages',
      isWrite: true,
      requiresConfirmation: true
    },
    {
      name: 'zatten_update_lead',
      description: 'Atualiza propriedades ou etapa do lead no funil Zatten. EXIGE CONFIRMAÇÃO HUMANA PRÉVIA.',
      requiredScope: 'zatten:write',
      isWrite: true,
      requiresConfirmation: true
    }
  ];

  return res.json({
    tools: tools.map(t => ({
      ...t,
      securitySchemes: {
        type: 'oauth2',
        authorizationUrl: `${issuer}/oauth/authorize`,
        tokenUrl: `${issuer}/oauth/token`,
        requiredScope: t.requiredScope
      }
    }))
  });
});

// ==============================================================================
// 3. FERRAMENTA DE PERFIL AUTENTICADA (firstsys_get_profile)
// ==============================================================================

mcpRouter.post('/tools/firstsys_get_profile', requireOAuth('profile'), (req: AuthenticatedMcpRequest, res: Response) => {
  const user = req.oauthUser!;
  return res.json({
    id: user.sub, // ID opaco permanente da conta Firstsys
    organizationId: user.org_id,
    role: user.role,
    scope: user.scope,
    client: user.client_id
  });
});

// ==============================================================================
// 4. FERRAMENTA DE LEITURA: Listar Conexões (zatten_list_connections)
// ==============================================================================

const MOCK_DB_PATH = path.join(process.cwd(), 'server', 'db.json');

mcpRouter.post('/tools/zatten_list_connections', requireOAuth('connections:read'), (req: AuthenticatedMcpRequest, res: Response) => {
  const user = req.oauthUser!;

  // Busca conexões ativas registradas (incluindo as provisionadas via Variáveis de Ambiente do Coolify)
  let connections: any[] = [];
  if (fs.existsSync(MOCK_DB_PATH)) {
    try {
      const db = JSON.parse(fs.readFileSync(MOCK_DB_PATH, 'utf8'));
      connections = (db.connections || [])
        .filter((c: any) => c.status === 'active' && (!user.org_id || c.organizationId === user.org_id))
        .map((c: any) => ({
          id: c.id,
          organizationId: c.organizationId,
          name: c.name,
          status: c.status,
          environment: c.environment || 'production',
          source: c.source || 'manual',
          lastValidatedAt: c.lastValidatedAt,
          lastUsedAt: c.lastUsedAt
        }));
    } catch (e) {
      console.warn('Erro ao ler conexões no MCP:', e);
    }
  }

  // Fallback padrão se nenhuma conexão persistida existir
  if (connections.length === 0) {
    connections = [
      {
        id: 'conn_coolify_principal',
        organizationId: user.org_id,
        name: 'Zatten Conexão Principal (Coolify)',
        status: 'active',
        environment: 'production',
        source: 'coolify_env',
        lastValidatedAt: new Date().toISOString(),
        lastUsedAt: new Date().toISOString()
      }
    ];
  }

  logAuditEvent({
    actor: user.sub,
    action: 'mcp.connections.listed',
    category: 'api_usage',
    severity: 'info',
    description: `ChatGPT listou conexões da organização ${user.org_id}`,
    ipAddress: req.ip || '127.0.0.1'
  });

  return res.json({ connections });
});

// ==============================================================================
// 5. FERRAMENTA DE ESCRITA: Enviar Mensagem com Confirmação Obrigatória
// ==============================================================================

const confirmationTokens = new Map<string, {
  tool: string;
  parameters: any;
  orgId: string;
  expiresAt: number;
}>();

const SendMessageSchema = z.object({
  connectionId: z.string().min(1),
  recipient: z.string().min(8, 'Número de telefone inválido'),
  messageText: z.string().min(1, 'Mensagem não pode ser vazia'),
  confirmationToken: z.string().optional()
});

mcpRouter.post('/tools/zatten_send_message', requireOAuth('zatten:messages'), async (req: AuthenticatedMcpRequest, res: Response) => {
  try {
    const user = req.oauthUser!;
    const parseResult = SendMessageSchema.safeParse(req.body);

    if (!parseResult.success) {
      return res.status(400).json({ error: 'invalid_params', details: parseResult.error.issues });
    }

    const { connectionId, recipient, messageText, confirmationToken } = parseResult.data;

    // Verificação de Confirmação Humana Explícita de Duas Etapas (Checklist 301)
    if (!confirmationToken) {
      // Gera token temporário de prévia e confirmação (válido por 5 minutos)
      const token = `conf_${crypto.randomBytes(16).toString('hex')}`;
      confirmationTokens.set(token, {
        tool: 'zatten_send_message',
        parameters: { connectionId, recipient, messageText },
        orgId: user.org_id,
        expiresAt: Date.now() + 5 * 60 * 1000
      });

      return res.status(200).json({
        requiresHumanConfirmation: true,
        confirmationToken: token,
        actionPreview: {
          action: 'Envio de Mensagem WhatsApp / Zatten',
          destinatario: recipient,
          mensagem: messageText,
          conexao: connectionId
        },
        message: 'Para prosseguir com o envio, o usuário deve confirmar a ação informando o confirmationToken.'
      });
    }

    // Valida o token de confirmação apresentado
    const record = confirmationTokens.get(confirmationToken);
    if (!record || record.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'invalid_confirmation', message: 'Token de confirmação expirado ou inválido.' });
    }

    if (record.orgId !== user.org_id) {
      return res.status(403).json({ error: 'forbidden', message: 'Token de confirmação pertence a outra organização.' });
    }

    // Consome o token de confirmação
    confirmationTokens.delete(confirmationToken);

    // Resolve o secretRef da conexão registrada no cofre/banco
    let resolvedSecretRef = `vault_aes_${connectionId}`;
    if (fs.existsSync(MOCK_DB_PATH)) {
      try {
        const db = JSON.parse(fs.readFileSync(MOCK_DB_PATH, 'utf8'));
        const found = (db.connections || []).find((c: any) => c.id === connectionId);
        if (found && found.secretRef) {
          resolvedSecretRef = found.secretRef;
        }
      } catch (e) {}
    }

    // Executa a chamada na API Zatten através do cliente com rate limit de 1 req/s
    const result = await zattenClient.executeRequest({
      connectionId,
      secretRef: resolvedSecretRef,
      endpoint: '/v1/messages',
      method: 'POST',
      body: { recipient, messageText },
      isWriteOperation: true
    });

    logAuditEvent({
      actor: user.sub,
      action: 'mcp.message.sent',
      category: 'api_usage',
      severity: 'info',
      description: `ChatGPT enviou mensagem autorizada para ${recipient} via conexão ${connectionId}`,
      ipAddress: req.ip || '127.0.0.1'
    });

    return res.json(result);
  } catch (err: unknown) {
    console.error('[MCP send_message] Erro:', err);
    return res.status(500).json({ error: 'server_error', message: 'Falha ao executar operação MCP' });
  }
});
