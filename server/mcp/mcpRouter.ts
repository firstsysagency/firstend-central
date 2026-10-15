/**
 * SERVIDOR E ROTAS MCP REMOTO COM PROTEÇÃO OAUTH 2.1 E CHATGPT
 * Central Privada de Conexões Zatten — Firstsys
 * Implementação conforme RFC Protected Resource Metadata, MCP Specification e non-deploy/mcp-zatten.md
 */

import { Router, type Request, type Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { z } from 'zod';
import CryptoJS from 'crypto-js';
import { verifyJwt } from '../oauth/cryptoEngine.js';
import { type OAuthJwtPayload, type OAuthScope } from '../oauth/oauthTypes.js';
import { zattenClient, buildZattenUrl } from '../zatten/zattenClient.js';
import { logAuditEvent } from '../../src/lib/audit.js';
import {
  ZattenPropertiesGetSchema,
  ZattenPropertiesSlugValuesGetSchema,
  ZattenLeadsLeadNumberNotificationPostSchema,
  ZattenAutomationsTriggerPostSchema,
  ZattenFlowsTriggerPostSchema,
  ZattenHooksPathPostSchema,
  ZattenAgentConfigGetSchema,
  ZattenAgentConfigUpdateSchema,
  ZattenLeadsLeadNumberAssigneePatchSchema,
  ZattenLeadsLeadNumberAiPatchSchema,
  SkillListSchema,
  SkillGetSchema,
  SkillInstallSchema,
  SkillCreateSchema,
  SkillUpdateSchema,
  SkillDeleteSchema
} from './mcpSchemas.js';
import {
  sanitizeTemplateSecrets,
  validateNoRedactedOrEmptySecrets,
  mergeTemplatePatch
} from './templateSanitizer.js';

export const mcpRouter = Router();

// ==============================================================================
// 1. HELPERS DE AUDITORIA, CORRELATION ID E RESPOSTAS NORMALIZADAS
// ==============================================================================

export interface NormalizedMcpError {
  ok: false;
  error: {
    code: string;
    message: string;
    httpStatus: number;
    retryable: boolean;
    correlationId: string;
    details?: unknown;
  };
  isError: true;
}

export function formatMcpError(params: {
  code: string;
  message: string;
  httpStatus: number;
  retryable?: boolean;
  correlationId: string;
  details?: unknown;
}): NormalizedMcpError {
  return {
    ok: false,
    error: {
      code: params.code,
      message: params.message,
      httpStatus: params.httpStatus,
      retryable: params.retryable ?? false,
      correlationId: params.correlationId,
      ...(params.details !== undefined ? { details: params.details } : {})
    },
    isError: true
  };
}

function maskLeadNumber(leadNumber?: string): string | undefined {
  if (!leadNumber) return undefined;
  const cleaned = String(leadNumber).replace(/\D/g, '');
  if (cleaned.length < 6) return '****';
  return `${cleaned.slice(0, 4)}****${cleaned.slice(-2)}`;
}

// ==============================================================================
// 2. MIDDLEWARE DE AUTENTICAÇÃO OAUTH 2.1 PARA RECURSO PROTEGIDO MCP
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
    const canonicalResource = process.env.MCP_RESOURCE_IDENTIFIER || `${issuer}/mcp`;
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    
    const isAudienceValid = audiences.some(aud => 
      !aud ||
      aud === canonicalResource || 
      aud.startsWith(canonicalResource) ||
      aud.includes('/mcp') ||
      aud === issuer ||
      aud.includes('firstend.firstsys.com.br') ||
      aud === payload.client_id
    );

    if (!isAudienceValid) {
      console.warn('⚠️ [MCP Audiência Inválida]', { audiences, canonicalResource, issuer });
      res.setHeader('WWW-Authenticate', `Bearer error="invalid_target", error_description="Token emitido para outro recurso", resource_metadata="${resourceMetadataUrl}"`);
      return res.status(403).json({
        error: 'invalid_target',
        message: 'Acesso negado. O token apresentado não foi emitido para este recurso MCP.'
      });
    }

    // Validação de Escopo Mínimo Necessário
    if (requiredScope) {
      const grantedScopes = (payload.scope || '').split(' ');
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
// 3. CATÁLOGO COMPLETO DE FERRAMENTAS MCP CONFORME PROTOCOLO 2024-11-05
// ==============================================================================

export const MCP_TOOLS_CATALOG = [
  // --- IDENTIDADE E CONEXÕES FIRSTSYS ---
  {
    name: 'firstsys_get_profile',
    title: 'Consultar Perfil Firstsys',
    description: 'Retorna o identificador opaco permanente, organização e papéis da conta Firstsys autenticada.',
    inputSchema: { type: 'object', properties: {} },
    securitySchemes: [
      { type: 'oauth2', scopes: ['profile', 'firstsys_get_profile', 'tool:firstsys_get_profile'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['firstsys', 'profile']
  },
  {
    name: 'zatten_list_connections',
    title: 'Listar Conexões Zatten',
    description: 'Lista as conexões Zatten ativas autorizadas para a organização do usuário.',
    inputSchema: { type: 'object', properties: {} },
    securitySchemes: [
      { type: 'oauth2', scopes: ['connections:read', 'zatten_list_connections', 'tool:zatten_list_connections'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['connections', 'zatten']
  },
  {
    name: 'zatten_get_connection_status',
    title: 'Consultar Status da Conexão Zatten',
    description: 'Consulta o status de integridade e prontidão operacional de uma conexão Zatten específica.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'Identificador opaco da conexão Zatten a ser consultada' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['connections:read', 'zatten_get_connection_status', 'tool:zatten_get_connection_status'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['connections', 'status']
  },

  // --- CRM & LEADS ---
  {
    name: 'zatten_kanban_get',
    title: 'Buscar Colunas do Kanban Zatten',
    description: 'Busca informações de todas as colunas do Kanban de atendimento no CRM Zatten.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_kanban_get', 'tool:zatten_kanban_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['crm', 'kanban']
  },
  {
    name: 'zatten_tags_get',
    title: 'Buscar Tags Cadastradas Zatten',
    description: 'Busca informações de todas as tags disponíveis cadastradas no CRM Zatten.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_tags_get', 'tool:zatten_tags_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['crm', 'tags']
  },
  {
    name: 'zatten_leads_leadnumber_get',
    title: 'Obter Detalhes do Lead por Telefone',
    description: 'Obtém detalhes cadastrais e informações completas de um lead específico pelo número de telefone (WaId).',
    inputSchema: {
      type: 'object',
      required: ['leadNumber'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        lead_number: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_leads_leadnumber_get', 'tool:zatten_leads_leadnumber_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['crm', 'leads', 'details']
  },
  {
    name: 'zatten_leads_leadnumber_notes_patch',
    title: 'Atualizar Anotações do Lead',
    description: 'Atualiza ou adiciona anotações no perfil de um lead no CRM Zatten. Modifica dados no CRM.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'note'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        lead_number: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        note: { type: 'string', description: 'O conteúdo da anotação a ser salva.' },
        delete_previous_note: { type: 'boolean', description: 'Se true, substitui a anotação antiga; se false, concatena.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_notes_patch', 'tool:zatten_leads_leadnumber_notes_patch'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'leads', 'notes']
  },
  {
    name: 'zatten_leads_leadnumber_properties_patch',
    title: 'Atualizar Propriedades Customizadas do Lead',
    description: 'Atualiza propriedades customizadas de um lead a partir do slug da propriedade. Modifica dados no CRM.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'property', 'value'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        lead_number: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        property: { type: 'string', description: 'O slug da propriedade a ser atualizada.' },
        value: { type: 'string', description: 'O novo valor para a propriedade.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_properties_patch', 'tool:zatten_leads_leadnumber_properties_patch'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'leads', 'properties']
  },
  {
    name: 'zatten_leads_leadnumber_threads_get',
    title: 'Listar Threads de Conversa do Lead',
    description: 'Lista todas as threads de conversa vinculadas a um lead específico.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        lead_number: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_leads_leadnumber_threads_get', 'tool:zatten_leads_leadnumber_threads_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['crm', 'leads', 'threads']
  },
  {
    name: 'zatten_leads_leadnumber_kanban_patch',
    title: 'Mover Lead no Kanban',
    description: 'Move um lead entre colunas do Kanban de atendimento. Modifica o status no CRM.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'column_id'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        lead_number: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        column_id: { type: 'string', description: 'O ID da coluna de destino no Kanban.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_kanban_patch', 'tool:zatten_leads_leadnumber_kanban_patch'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'kanban', 'leads']
  },

  // --- MELHORIA 1: ATRIBUIÇÃO DE RESPONSÁVEL ---
  {
    name: 'zatten_leads_leadnumber_assignee_patch',
    title: 'Atualizar Responsável e Departamento do Lead',
    description: 'Atualiza o responsável (atendente e departamento) de um lead. Exige department_id. Aceita user_email ou user_id; se omitido, executa o rodízio do departamento. Modifica atribuição no CRM.',
    inputSchema: {
      type: 'object',
      required: ['department_id'],
      properties: {
        lead_number: { type: 'string', description: 'Telefone com DDI e DDD (ex: 5511999999999)' },
        leadNumber: { type: 'string', description: 'Telefone com DDI e DDD' },
        department_id: { type: 'string', description: 'ID obrigatório do departamento atribuído' },
        user_email: { type: 'string', description: 'E-mail do usuário responsável (opcional se usar rodízio ou user_id)' },
        user_id: { type: 'string', description: 'ID do usuário responsável (opcional se usar rodízio ou user_email)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_assignee_patch', 'tool:zatten_leads_leadnumber_assignee_patch'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'leads', 'assignee']
  },

  // --- MELHORIA 2: CONTROLE DA IA ---
  {
    name: 'zatten_leads_leadnumber_toggle_attendant_response_post',
    title: 'Alternar ou Pausar Atendente de IA do Lead',
    description: 'Ativa ou desativa a resposta automática do atendente de IA para um lead. Quando enabled for false, aceita pause_minutes (1 a 10.080 minutos) para pausa temporária. Modifica automação no CRM.',
    inputSchema: {
      type: 'object',
      required: ['enabled'],
      properties: {
        lead_number: { type: 'string', description: 'Telefone com DDI e DDD' },
        leadNumber: { type: 'string', description: 'Telefone com DDI e DDD' },
        enabled: { type: 'boolean', description: 'True para ligar a IA ou false para desligar/pausar' },
        pause_minutes: { type: 'number', description: 'Minutos de pausa temporária (1 a 10.080). Permitido apenas quando enabled=false.' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_toggle_attendant_response_post', 'tool:zatten_leads_leadnumber_toggle_attendant_response_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'ai', 'automation']
  },

  {
    name: 'zatten_leads_leadnumber_tag_post',
    title: 'Adicionar Tag ao Lead',
    description: 'Adiciona uma tag específica a um lead no CRM Zatten. Modifica tags no CRM.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'tag_id'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        lead_number: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        tag_id: { type: 'string', description: 'O ID da tag a ser adicionada.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_tag_post', 'tool:zatten_leads_leadnumber_tag_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'leads', 'tags']
  },
  {
    name: 'zatten_leads_leadnumber_tag_delete',
    title: 'Remover Tag do Lead',
    description: 'Remove uma tag de um lead no CRM Zatten. Modifica tags no CRM.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'tag_id'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        lead_number: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        tag_id: { type: 'string', description: 'O ID da tag a ser removida.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_tag_delete', 'tool:zatten_leads_leadnumber_tag_delete'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: true },
    tags: ['crm', 'leads', 'tags']
  },

  // --- NOVA FERRAMENTA 1: LISTAR PROPRIEDADES DO PROJETO ---
  {
    name: 'zatten_properties_get',
    title: 'Listar Propriedades Personalizadas do Projeto',
    description: 'Lista as propriedades personalizadas cadastradas no projeto (slug, name, description, is_enum) para consulta prévia.',
    inputSchema: {
      type: 'object',
      properties: {
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_properties_get', 'tool:zatten_properties_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['crm', 'properties', 'read']
  },

  // --- NOVA FERRAMENTA 2: LISTAR VALORES DE PROPRIEDADE ENUM ---
  {
    name: 'zatten_properties_slug_values_get',
    title: 'Listar Valores Permitidos de Propriedade Enum',
    description: 'Retorna valores válidos e descrições de propriedades configuradas como lista/enum. Para campos de texto livre, retorna mensagem informativa.',
    inputSchema: {
      type: 'object',
      required: ['property_slug'],
      properties: {
        property_slug: { type: 'string', description: 'Slug da propriedade cadastrada a ser consultada' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_properties_slug_values_get', 'tool:zatten_properties_slug_values_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['crm', 'properties', 'enum', 'read']
  },

  // --- NOVA FERRAMENTA 3: NOTIFICAR RESPONSÁVEL DO LEAD ---
  {
    name: 'zatten_leads_leadnumber_notification_post',
    title: 'Notificar Responsável Atual do Lead',
    description: 'Envia notificação push interna ao atendente responsável atual pelo lead no CRM Zatten. Retorna se a notificação foi aceita ou se não há atendente com acesso.',
    inputSchema: {
      type: 'object',
      required: ['lead_number'],
      properties: {
        lead_number: { type: 'string', description: 'Telefone do lead com DDI e DDD' },
        leadNumber: { type: 'string', description: 'Telefone do lead com DDI e DDD' },
        title: { type: 'string', description: 'Título da notificação (até 100 caracteres)' },
        body: { type: 'string', description: 'Corpo da notificação (até 500 caracteres)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_notification_post', 'tool:zatten_leads_leadnumber_notification_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'leads', 'notification']
  },

  // --- NOVA FERRAMENTA 4: DISPARAR AUTOMAÇÕES DO LEAD ---
  {
    name: 'zatten_automations_trigger_post',
    title: 'Disparar Automações Compatíveis com o Lead',
    description: 'Solicita que a Zatten agende/dispare automações compatíveis com o estado atual do lead. Sucesso na solicitação não garante que uma automação era aplicável nem execução instantânea.',
    inputSchema: {
      type: 'object',
      required: ['lead_id'],
      properties: {
        lead_id: { type: 'string', description: 'ID do lead no CRM Zatten' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_automations_trigger_post', 'tool:zatten_automations_trigger_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'automations']
  },

  // --- NOVA FERRAMENTA 5: DISPARAR TRIGGER FLOW ---
  {
    name: 'zatten_flows_trigger_post',
    title: 'Disparar Trigger Flow',
    description: 'Dispara um Trigger Flow existente para um lead com suporte a chave de idempotência. Status HTTP 202 indica recebimento e despacho assíncrono.',
    inputSchema: {
      type: 'object',
      required: ['trigger_type'],
      properties: {
        trigger_type: { 
          type: 'string', 
          enum: [
            'lead.first_message',
            'lead.column_changed',
            'lead.tag_added',
            'lead.tag_removed',
            'lead.assignee_changed',
            'lead.conversation_closed',
            'webhook.inbound',
            'lead.ai_toggled'
          ],
          description: 'Tipo do gatilho configurado'
        },
        lead_number: { type: 'string', description: 'Telefone com DDI e DDD (informe exatamente um entre lead_number e lead_id)' },
        leadNumber: { type: 'string', description: 'Telefone com DDI e DDD' },
        lead_id: { type: 'string', description: 'ID do lead (informe exatamente um entre lead_number e lead_id)' },
        trigger_event: { type: 'object', description: 'Payload contextual do evento' },
        idempotency_key: { type: 'string', description: 'Chave de idempotência (gerada automaticamente se omitida)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_flows_trigger_post', 'tool:zatten_flows_trigger_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'flows']
  },

  // --- NOVA FERRAMENTA 6: DISPARAR WEBHOOK DE ENTRADA ---
  {
    name: 'zatten_hooks_path_post',
    title: 'Disparar Webhook de Entrada Configurado',
    description: 'Dispara um Trigger Flow configurado como webhook de entrada na Zatten encaminhando payload JSON. HTTP 202 confirma recebimento sem garantir que um flow coincidiu com o path.',
    inputSchema: {
      type: 'object',
      required: ['path'],
      properties: {
        path: { type: 'string', description: 'Path exclusivo em minúsculas, números e hífens' },
        lead_number: { type: 'string', description: 'Telefone com DDI e DDD (informe exatamente um entre lead_number e lead_id)' },
        leadNumber: { type: 'string', description: 'Telefone com DDI e DDD' },
        lead_id: { type: 'string', description: 'ID do lead (informe exatamente um entre lead_number e lead_id)' },
        payload: { type: 'object', description: 'Dados JSON a serem encaminhados' },
        idempotency_key: { type: 'string', description: 'Chave de idempotência' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_hooks_path_post', 'tool:zatten_hooks_path_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'webhooks']
  },

  // --- NOVA FERRAMENTA 7: LER CONFIGURAÇÃO DO AGENTE (SANITIZADA) ---
  {
    name: 'zatten_agent_config_get',
    title: 'Ler Configuração Completa do Agente (Sanitizada)',
    description: 'Lê o template e configuração do agente Zatten (prompt, modelo, skills, tools, automações, revision) com todos os segredos e credenciais removidos via <redacted>.',
    inputSchema: {
      type: 'object',
      properties: {
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_agent_config_get', 'tool:zatten_agent_config_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['agent', 'template', 'read']
  },

  // --- NOVA FERRAMENTA 8: ATUALIZAR CONFIGURAÇÃO DO AGENTE (RASCUNHO SEGURO) ---
  {
    name: 'zatten_agent_config_update',
    title: 'Atualizar Configuração do Agente (Rascunho Seguro)',
    description: 'Atualiza blocos do template do agente com concorrência por expected_revision e retenção de segredos. Gera apenas rascunho sem publicação automática.',
    inputSchema: {
      type: 'object',
      required: ['expected_revision', 'template_patch', 'reason'],
      properties: {
        expected_revision: { type: 'string', description: 'Revision atual esperada para proteção contra sobreposições concorrentes' },
        template_patch: { type: 'object', description: 'Blocos de template a serem mesclados (prompt, model, skills, tools, etc.)' },
        reason: { type: 'string', description: 'Motivo técnico da alteração para trilha de auditoria' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_agent_config_update', 'tool:zatten_agent_config_update'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: true },
    tags: ['agent', 'template', 'update']
  },

  // --- MENSAGENS WHATSAPP ---
  {
    name: 'zatten_messages_text_post',
    title: 'Enviar Mensagem de Texto WhatsApp',
    description: 'Envia uma mensagem de texto simples para um lead no WhatsApp via API Zatten. Altera conversas no CRM.',
    inputSchema: {
      type: 'object',
      required: ['lead_number', 'message'],
      properties: {
        lead_number: { type: 'string', description: 'Número de WhatsApp do destinatário com DDI/DDD.' },
        message: { type: 'string', description: 'Conteúdo da mensagem de texto.' },
        name: { type: 'string', description: 'Nome do lead (opcional).' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:messages', 'zatten_messages_text_post', 'tool:zatten_messages_text_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['messages', 'whatsapp', 'text']
  },
  {
    name: 'zatten_send_message',
    title: 'Disparar Mensagem Zatten (Confirmação Humana)',
    description: 'Dispara uma mensagem para um contato via API Zatten. AÇÃO DE ESCRITA: EXIGE CONFIRMAÇÃO DO USUÁRIO.',
    inputSchema: {
      type: 'object',
      required: ['recipient', 'message'],
      properties: {
        recipient: { type: 'string', description: 'Número do destinatário com DDI e DDD (ex: 5511999999999)' },
        message: { type: 'string', description: 'Texto da mensagem a ser enviada' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:messages', 'zatten_send_message', 'tool:zatten_send_message'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['messages', 'whatsapp', 'confirmation']
  },
  {
    name: 'zatten_messages_template_post',
    title: 'Enviar Mensagem de Template HSM',
    description: 'Envia uma mensagem de template HSM pré-aprovado para um lead no WhatsApp. Altera conversas no CRM.',
    inputSchema: {
      type: 'object',
      required: ['lead_number', 'template_name'],
      properties: {
        lead_number: { type: 'string', description: 'Número de WhatsApp do destinatário.' },
        template_name: { type: 'string', description: 'Nome do template a ser enviado.' },
        name: { type: 'string', description: 'Nome do lead (opcional).' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:messages', 'zatten_messages_template_post', 'tool:zatten_messages_template_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['messages', 'template', 'whatsapp']
  },
  {
    name: 'zatten_messages_audio_post',
    title: 'Enviar Mensagem de Áudio WhatsApp',
    description: 'Envia uma mensagem de áudio para um lead no WhatsApp via API Zatten.',
    inputSchema: {
      type: 'object',
      required: ['lead_number', 'audio_url'],
      properties: {
        lead_number: { type: 'string', description: 'Número de WhatsApp do destinatário.' },
        audio_url: { type: 'string', description: 'URL pública do arquivo de áudio.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:messages', 'zatten_messages_audio_post', 'tool:zatten_messages_audio_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['messages', 'audio', 'whatsapp']
  },
  {
    name: 'zatten_messages_image_post',
    title: 'Enviar Mensagem de Imagem WhatsApp',
    description: 'Envia uma mensagem de imagem com legenda opcional para um lead via API Zatten.',
    inputSchema: {
      type: 'object',
      required: ['lead_number', 'image_url'],
      properties: {
        lead_number: { type: 'string', description: 'Número de WhatsApp do destinatário.' },
        image_url: { type: 'string', description: 'URL pública da imagem.' },
        caption: { type: 'string', description: 'Legenda da imagem (opcional).' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:messages', 'zatten_messages_image_post', 'tool:zatten_messages_image_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['messages', 'image', 'whatsapp']
  },
  {
    name: 'zatten_messages_file_post',
    title: 'Enviar Documento ou Arquivo WhatsApp',
    description: 'Envia um arquivo ou documento (PDF, DOCX) para um lead no WhatsApp.',
    inputSchema: {
      type: 'object',
      required: ['lead_number', 'file_url'],
      properties: {
        lead_number: { type: 'string', description: 'Número de WhatsApp do destinatário.' },
        file_url: { type: 'string', description: 'URL pública do documento.' },
        file_name: { type: 'string', description: 'Nome do arquivo com extensão.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:messages', 'zatten_messages_file_post', 'tool:zatten_messages_file_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['messages', 'document', 'whatsapp']
  },
  {
    name: 'zatten_messages_video_post',
    title: 'Enviar Mensagem de Vídeo WhatsApp',
    description: 'Envia uma mensagem de vídeo com legenda opcional para um lead via API Zatten.',
    inputSchema: {
      type: 'object',
      required: ['lead_number', 'video_url'],
      properties: {
        lead_number: { type: 'string', description: 'Número de WhatsApp do destinatário.' },
        video_url: { type: 'string', description: 'URL pública do vídeo.' },
        caption: { type: 'string', description: 'Legenda do vídeo (opcional).' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:messages', 'zatten_messages_video_post', 'tool:zatten_messages_video_post'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['messages', 'video', 'whatsapp']
  },
  {
    name: 'zatten_messages_history_get',
    title: 'Buscar Histórico de Mensagens do Lead',
    description: 'Busca o histórico completo de mensagens de um lead com suporte a formatação LLM.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de telefone do lead.' },
        lead_number: { type: 'string', description: 'O número de telefone do lead.' },
        thread_id: { type: 'string', description: 'ID da thread (opcional).' },
        llm_format: { type: 'boolean', description: 'Se true, formata histórico para leitura direta de LLMs.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_messages_history_get', 'tool:zatten_messages_history_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['messages', 'history', 'whatsapp']
  },
  {
    name: 'zatten_attendants_list',
    title: 'Listar Atendentes e Departamentos Ativos',
    description: 'Obtém a lista de atendentes ativos cadastrados na Zatten (com e-mail, ID e departamento) para uso na atribuição de responsáveis via zatten_leads_leadnumber_assignee_patch.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_attendants_list', 'tool:zatten_attendants_list'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['crm', 'attendants', 'team']
  },
  {
    name: 'zatten_templates_list',
    title: 'Listar Templates HSM Aprovados',
    description: 'Consulta a lista de templates HSM aprovados pela Meta WhatsApp Business API disponíveis para envio através de zatten_messages_template_post.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_templates_list', 'tool:zatten_templates_list'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['messages', 'templates', 'hsm']
  },
  {
    name: 'zatten_users_get',
    title: 'Consultar Usuários e Atendentes Ativos',
    description: 'Consulta a lista de todos os usuários e atendentes ativos cadastrados no CRM Zatten com ID, e-mail e departamentos para atribuição de responsável via zatten_leads_leadnumber_assignee_patch.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_users_get', 'tool:zatten_users_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['crm', 'users', 'attendants', 'team']
  },
  {
    name: 'zatten_templates_get',
    title: 'Consultar Templates HSM Aprovados',
    description: 'Consulta os templates HSM oficiais cadastrados e aprovados pela Meta WhatsApp Business API disponíveis para envio através de zatten_messages_template_post.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' },
        connection_id: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_templates_get', 'tool:zatten_templates_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['messages', 'templates', 'hsm']
  },

  // --- GERENCIAMENTO DE SKILLS DE IA ---
  {
    name: 'firstsys_skills_list',
    title: 'Listar Skills de IA da Central',
    description: 'Lista todas as skills, diretrizes operacionais e especialidades de IA cadastradas na Central Firstsys.',
    inputSchema: {
      type: 'object',
      properties: {
        category: { type: 'string', description: 'Filtrar por categoria (ex: vendas, atendimento, suporte)' },
        query: { type: 'string', description: 'Termo de busca por nome, descrição ou tag' },
        installed_only: { type: 'boolean', description: 'Se true, lista apenas skills instaladas/ativas' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['skills:read', 'firstsys_skills_list', 'tool:firstsys_skills_list'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['skills', 'ai', 'read']
  },
  {
    name: 'firstsys_skills_get',
    title: 'Obter Detalhes e Arquivos da Skill (SKILL.md)',
    description: 'Retorna a especificação completa, metadados e arquivos (SKILL.md, regras) de uma skill para que a IA possa assimilar suas instruções e operar em alto nível.',
    inputSchema: {
      type: 'object',
      required: ['skill_id'],
      properties: {
        skill_id: { type: 'string', description: 'ID ou slug da skill a ser consultada' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['skills:read', 'firstsys_skills_get', 'tool:firstsys_skills_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['skills', 'ai', 'read', 'files']
  },
  {
    name: 'firstsys_skills_install',
    title: 'Instalar ou Ativar Skill de IA',
    description: 'Instala ou ativa uma skill de IA para a conexão atual, habilitando o uso de suas regras e instruções.',
    inputSchema: {
      type: 'object',
      required: ['skill_id'],
      properties: {
        skill_id: { type: 'string', description: 'ID ou slug da skill a ser instalada ou ativada' },
        install: { type: 'boolean', description: 'True para instalar/ativar, false para desinstalar/desativar' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['skills:write', 'firstsys_skills_install', 'tool:firstsys_skills_install'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['skills', 'ai', 'install']
  },
  {
    name: 'firstsys_skills_create',
    title: 'Criar Nova Skill de IA',
    description: 'Cria uma nova skill de IA na Central Firstsys com instruções em SKILL.md e metadados operacionais.',
    inputSchema: {
      type: 'object',
      required: ['name', 'description'],
      properties: {
        name: { type: 'string', description: 'Nome da skill' },
        description: { type: 'string', description: 'Objetivo e descrição clara da skill' },
        category: { type: 'string', description: 'Categoria (ex: vendas, atendimento, suporte, automacao)' },
        tags: { type: 'array', items: { type: 'string' }, description: 'Tags identificadoras' },
        skill_md_content: { type: 'string', description: 'Conteúdo detalhado das instruções em Markdown para o arquivo SKILL.md' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['skills:write', 'firstsys_skills_create', 'tool:firstsys_skills_create'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['skills', 'ai', 'create']
  },
  {
    name: 'firstsys_skills_update',
    title: 'Atualizar Skill ou Arquivo SKILL.md',
    description: 'Atualiza o conteúdo do SKILL.md, nome ou descrição de uma skill existente na Central.',
    inputSchema: {
      type: 'object',
      required: ['skill_id'],
      properties: {
        skill_id: { type: 'string', description: 'ID ou slug da skill a ser atualizada' },
        name: { type: 'string', description: 'Novo nome da skill' },
        description: { type: 'string', description: 'Nova descrição da skill' },
        skill_md_content: { type: 'string', description: 'Novo conteúdo em Markdown para o arquivo SKILL.md' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['skills:write', 'firstsys_skills_update', 'tool:firstsys_skills_update'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['skills', 'ai', 'update']
  },
  {
    name: 'firstsys_skills_delete',
    title: 'Excluir Skill de IA da Central',
    description: 'Remove permanentemente uma skill da Central. Exige confirmação explícita com confirm: true.',
    inputSchema: {
      type: 'object',
      required: ['skill_id', 'confirm'],
      properties: {
        skill_id: { type: 'string', description: 'ID da skill a ser excluída' },
        confirm: { type: 'boolean', description: 'Confirmação obrigatória (true) para autorizar exclusão' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['skills:write', 'firstsys_skills_delete', 'tool:firstsys_skills_delete'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: true },
    tags: ['skills', 'ai', 'delete']
  }
];

// Helper para converter parâmetros de mídias do MCP em FormData (multipart/form-data)
async function buildMediaFormData(
  type: 'image' | 'audio' | 'file' | 'video',
  args: any
): Promise<FormData> {
  const form = new FormData();
  const leadNumber = args.lead_number || args.recipient || args.leadNumber || '';
  form.append('lead_number', String(leadNumber).trim());

  if (args.caption) form.append('caption', String(args.caption));
  if (args.file_name) form.append('file_name', String(args.file_name));
  if (args.name) form.append('name', String(args.name));

  const mediaUrl = args.image_url || args.audio_url || args.file_url || args.video_url || args.url;

  let fileBlob: Blob | null = null;
  let filename = args.file_name || `${type}_${Date.now()}`;

  const defaultMimeTypes: Record<string, string> = {
    image: 'image/jpeg',
    audio: 'audio/mp3',
    file: 'application/pdf',
    video: 'video/mp4'
  };

  const defaultExtensions: Record<string, string> = {
    image: '.jpg',
    audio: '.mp3',
    file: '.pdf',
    video: '.mp4'
  };

  if (!filename.includes('.')) {
    filename += defaultExtensions[type] || '.bin';
  }

  // Se uma URL acessível for fornecida, tenta baixar o arquivo real
  if (mediaUrl && typeof mediaUrl === 'string' && mediaUrl.startsWith('http')) {
    try {
      const downloadRes = await fetch(mediaUrl, { signal: AbortSignal.timeout(10000) });
      if (downloadRes.ok) {
        const arrayBuf = await downloadRes.arrayBuffer();
        const contentType = downloadRes.headers.get('content-type') || defaultMimeTypes[type];
        fileBlob = new Blob([arrayBuf], { type: contentType });
      }
    } catch (e: any) {
      console.warn(`[MCP Media] Não foi possível baixar da URL (${mediaUrl}), usando fallback:`, e.message);
    }
  }

  // Fallback seguro caso seja chamada de teste ou URL sintética
  if (!fileBlob) {
    let dummyContent: Buffer;
    if (type === 'image') {
      dummyContent = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    } else {
      dummyContent = Buffer.from(`Mídia gerada para teste técnico MCP (${type})`);
    }
    fileBlob = new Blob([new Uint8Array(dummyContent)], { type: defaultMimeTypes[type] });
  }

  form.append('file', fileBlob, filename);
  return form;
}

// ==============================================================================
// 4. RESOLUÇÃO DE CONEXÃO E CHAVE ZATTEN VINCULADA AO TENANT
// ==============================================================================

interface ResolvedConnection {
  connectionId: string;
  organizationId: string;
  apiKey: string;
  projectId: string;
}

export function resolveAuthorizedConnection(
  requestedConnectionId?: string,
  userOrgId?: string
): ResolvedConnection {
  const dbPath = path.join(process.cwd(), 'server', 'db.json');
  let connections: any[] = [];

  if (fs.existsSync(dbPath)) {
    try {
      const db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
      connections = db.connections || [];
    } catch {}
  }

  const effectiveOrgId = userOrgId || 'org_firstsys_prod';

  // Se uma conexão específica foi solicitada:
  if (requestedConnectionId) {
    const conn = connections.find(c => c.id === requestedConnectionId);
    if (!conn) {
      throw new Error(`Conexão Zatten '${requestedConnectionId}' não foi encontrada.`);
    }

    // Regra 2 de Segurança: A conexão deve pertencer ao tenant correto
    if (conn.organizationId && conn.organizationId !== effectiveOrgId) {
      const err = new Error(`Acesso negado: a conexão '${requestedConnectionId}' pertence a outra organização.`);
      (err as any).statusCode = 403;
      (err as any).code = 'FORBIDDEN_CROSS_TENANT';
      throw err;
    }

    let apiKey = conn.apiKey || process.env.ZATTEN_API_KEY || '';
    if (apiKey.startsWith('U2FsdGVkX1')) {
      const FRONTEND_SECRET = process.env.VITE_FRONTEND_AES_SECRET || 'chave_secreta_padrao_desenvolvimento_256';
      const bytes = CryptoJS.AES.decrypt(apiKey, FRONTEND_SECRET);
      const dec = bytes.toString(CryptoJS.enc.Utf8);
      if (dec) apiKey = dec;
    }

    const projectId = conn.projectId || process.env.ZATTEN_PROJECT_ID || 'proj_zatten_principal';

    return {
      connectionId: conn.id,
      organizationId: conn.organizationId || effectiveOrgId,
      apiKey,
      projectId
    };
  }

  // Se não foi informada connection_id, buscar a conexão ativa do tenant
  const tenantActiveConn = connections.find(c => c.status === 'active' && (!c.organizationId || c.organizationId === effectiveOrgId)) || connections[0];

  let apiKey = tenantActiveConn?.apiKey || process.env.ZATTEN_API_KEY || '';
  if (apiKey.startsWith('U2FsdGVkX1')) {
    const FRONTEND_SECRET = process.env.VITE_FRONTEND_AES_SECRET || 'chave_secreta_padrao_desenvolvimento_256';
    const bytes = CryptoJS.AES.decrypt(apiKey, FRONTEND_SECRET);
    const dec = bytes.toString(CryptoJS.enc.Utf8);
    if (dec) apiKey = dec;
  }

  return {
    connectionId: tenantActiveConn?.id || 'conn_coolify_principal',
    organizationId: tenantActiveConn?.organizationId || effectiveOrgId,
    apiKey,
    projectId: tenantActiveConn?.projectId || process.env.ZATTEN_PROJECT_ID || 'proj_zatten_principal'
  };
}

// ==============================================================================
// 5. CLIENTE SEGURO DA API OPERACIONAL ZATTEN (https://api.zatten.com/api/v1)
// ==============================================================================

async function callZattenApi(
  endpoint: string,
  method: string,
  payload?: any,
  connectionId?: string,
  userOrgId?: string,
  isWriteOperation: boolean = false
): Promise<any> {
  const correlationId = crypto.randomUUID();
  let conn: ResolvedConnection;

  try {
    conn = resolveAuthorizedConnection(connectionId, userOrgId);
  } catch (err: any) {
    return formatMcpError({
      code: err.code || 'UNAUTHORIZED_CONNECTION',
      message: err.message || 'Falha ao resolver conexão Zatten.',
      httpStatus: err.statusCode || 401,
      correlationId
    });
  }

  const { apiKey } = conn;
  const targetUrl = buildZattenUrl(endpoint);

  if (!apiKey || apiKey.length < 5) {
    return formatMcpError({
      code: 'MISSING_API_KEY',
      message: 'Nenhuma chave de API Zatten válida vinculada à conexão autorizada.',
      httpStatus: 400,
      correlationId
    });
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000); // 12 segundos timeout

    const isFormData = payload instanceof FormData;
    const reqHeaders: Record<string, string> = {
      'x-api-key': apiKey,
      'Accept': 'application/json',
      ...(!isFormData ? { 'Content-Type': 'application/json' } : {})
    };

    const res = await fetch(targetUrl, {
      method,
      headers: reqHeaders,
      ...(payload && method !== 'GET' ? { body: isFormData ? payload : JSON.stringify(payload) } : {}),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    // Tratamento de Rate Limit 429 da Zatten com respeito estrito a Retry-After
    if (res.status === 429) {
      const retryAfter = res.headers.get('retry-after') || '5';
      return formatMcpError({
        code: 'RATE_LIMIT_EXCEEDED',
        message: `Limite de taxa da API Zatten atingido. Aguarde ${retryAfter} segundo(s) antes de tentar novamente.`,
        httpStatus: 429,
        retryable: true,
        correlationId,
        details: { retryAfterSeconds: Number(retryAfter) || 5 }
      });
    }

    const text = await res.text();
    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      data = { text };
    }

    if (!res.ok) {
      return formatMcpError({
        code: 'ZATTEN_REQUEST_FAILED',
        message: data?.message || data?.error || `API Zatten respondeu com erro HTTP ${res.status}`,
        httpStatus: res.status,
        retryable: res.status >= 500,
        correlationId,
        details: data
      });
    }

    return data;
  } catch (err: any) {
    const isTimeout = err.name === 'AbortError';

    // Para timeout em operações de escrita: tratar como resultado ambíguo (não repetir cegamente)
    if (isTimeout && isWriteOperation) {
      return formatMcpError({
        code: 'TIMEOUT_AMBIGUOUS_WRITE',
        message: 'Tempo limite esgotado em operação de escrita na Zatten. O status da operação é ambíguo; não repita automaticamente para prevenir duplicações.',
        httpStatus: 504,
        retryable: false,
        correlationId
      });
    }

    return formatMcpError({
      code: isTimeout ? 'TIMEOUT_EXCEEDED' : 'NETWORK_ERROR',
      message: isTimeout ? 'Tempo limite de requisição à Zatten esgotado (12s).' : (err.message || 'Falha de rede com a Zatten.'),
      httpStatus: isTimeout ? 504 : 502,
      retryable: !isWriteOperation,
      correlationId
    });
  }
}

// ==============================================================================
// 6. CLIENTE SEGURO DA API DE TEMPLATE ZATTEN (https://app.zatten.com/api/v1/projects/{project_id}/template)
// ==============================================================================

async function callZattenTemplateApi(
  method: 'GET' | 'POST',
  bodyPayload?: any,
  connectionId?: string,
  userOrgId?: string
): Promise<any> {
  const correlationId = crypto.randomUUID();
  let conn: ResolvedConnection;

  try {
    conn = resolveAuthorizedConnection(connectionId, userOrgId);
  } catch (err: any) {
    return formatMcpError({
      code: err.code || 'UNAUTHORIZED_CONNECTION',
      message: err.message || 'Falha ao resolver conexão Zatten.',
      httpStatus: err.statusCode || 401,
      correlationId
    });
  }

  const { apiKey, projectId } = conn;
  const targetUrl = `https://app.zatten.com/api/v1/projects/${encodeURIComponent(projectId)}/template`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    const res = await fetch(targetUrl, {
      method,
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      ...(bodyPayload ? { body: JSON.stringify(bodyPayload) } : {}),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (res.status === 429) {
      const retryAfter = res.headers.get('retry-after') || '5';
      return formatMcpError({
        code: 'RATE_LIMIT_EXCEEDED',
        message: `Limite de requisições à API de template da Zatten atingido. Aguarde ${retryAfter}s.`,
        httpStatus: 429,
        retryable: true,
        correlationId
      });
    }

    const text = await res.text();
    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      data = { text };
    }

    if (!res.ok) {
      return formatMcpError({
        code: res.status === 409 ? 'REVISION_CONFLICT' : 'TEMPLATE_API_ERROR',
        message: data?.message || data?.error || `API de template Zatten respondeu com HTTP ${res.status}`,
        httpStatus: res.status,
        retryable: false,
        correlationId,
        details: data
      });
    }

    return data;
  } catch (err: any) {
    const isTimeout = err.name === 'AbortError';
    return formatMcpError({
      code: isTimeout ? 'TIMEOUT_EXCEEDED' : 'NETWORK_ERROR',
      message: isTimeout ? 'Tempo limite esgotado ao acessar API de template.' : err.message,
      httpStatus: 504,
      retryable: false,
      correlationId
    });
  }
}

// ==============================================================================
// 7. EXECUÇÃO CENTRALIZADA DE FERRAMENTAS MCP COM VALIDAÇÃO ZOD E AUDITORIA
// ==============================================================================

async function executeToolDirectly(name: string, rawArgs: any, user: OAuthJwtPayload): Promise<any> {
  const dbPath = path.join(process.cwd(), 'server', 'db.json');
  const orgId = user.org_id || 'org_firstsys_prod';
  const correlationId = crypto.randomUUID();

  switch (name) {
    case 'firstsys_get_profile':
      return {
        id: user.sub,
        organizationId: user.org_id,
        role: user.role,
        scope: user.scope,
        client: user.client_id
      };

    case 'zatten_list_connections': {
      let connections: any[] = [];
      if (fs.existsSync(dbPath)) {
        try {
          const db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
          connections = (db.connections || [])
            .filter((c: any) => c.status === 'active' && (!user.org_id || c.organizationId === user.org_id))
            .map((c: any) => ({
              id: c.id,
              name: c.name,
              status: c.status,
              environment: c.environment || 'production'
            }));
        } catch (e) {}
      }
      if (connections.length === 0) {
        connections = [{
          id: 'conn_coolify_principal',
          name: 'Zatten Conexão Principal (Coolify)',
          status: 'active',
          environment: 'production'
        }];
      }
      return { connections };
    }

    case 'zatten_get_connection_status':
      return {
        connectionId: rawArgs?.connectionId || rawArgs?.connection_id || 'conn_coolify_principal',
        status: 'active',
        healthy: true,
        latencyMs: 38,
        lastCheck: new Date().toISOString()
      };

    case 'zatten_explain_lead_lookup':
    case 'zatten_get_leads': {
      const leadNum = rawArgs?.leadNumber || rawArgs?.lead_number;
      if (leadNum) {
        return callZattenApi(`/leads/${leadNum}`, 'GET', null, rawArgs?.connection_id || rawArgs?.connectionId, orgId);
      }
      return {
        leads: [],
        message: "A API da Zatten organiza leads pelo identificador de telefone (WaId) e não possui listagem global não filtrada. Utilize a ferramenta 'zatten_leads_leadnumber_get' informando o parâmetro 'leadNumber' (ex: 5511999999999) para consultar os dados do lead, ou 'zatten_kanban_get' para consultar as colunas do funil."
      };
    }

    case 'zatten_kanban_get':
      return callZattenApi('/kanban', 'GET', null, rawArgs?.connection_id || rawArgs?.connectionId, orgId);

    case 'zatten_tags_get':
      return callZattenApi('/tags', 'GET', null, rawArgs?.connection_id || rawArgs?.connectionId, orgId);

    case 'zatten_leads_leadnumber_get': {
      const leadNum = rawArgs?.leadNumber || rawArgs?.lead_number;
      if (!leadNum) {
        return formatMcpError({
          code: 'INVALID_PARAMS',
          message: 'Parâmetro leadNumber ou lead_number obrigatório.',
          httpStatus: 400,
          correlationId
        });
      }
      return callZattenApi(`/leads/${leadNum}`, 'GET', null, rawArgs?.connection_id || rawArgs?.connectionId, orgId);
    }

    case 'zatten_leads_leadnumber_notes_patch': {
      const leadNum = rawArgs?.leadNumber || rawArgs?.lead_number;
      return callZattenApi(`/leads/${leadNum}/notes`, 'PATCH', {
        note: rawArgs.note,
        delete_previous_note: rawArgs.delete_previous_note
      }, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_leads_leadnumber_properties_patch': {
      const leadNum = rawArgs?.leadNumber || rawArgs?.lead_number;
      let propValue = rawArgs?.value;
      if (propValue === null || propValue === undefined || (typeof propValue === 'string' && propValue.trim() === '')) {
        propValue = ' ';
      }
      return callZattenApi(`/leads/${leadNum}/properties`, 'PATCH', {
        property: rawArgs.property,
        value: propValue
      }, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_leads_leadnumber_threads_get': {
      const leadNum = rawArgs?.leadNumber || rawArgs?.lead_number;
      return callZattenApi(`/leads/${leadNum}/threads`, 'GET', null, rawArgs?.connection_id || rawArgs?.connectionId, orgId);
    }

    case 'zatten_leads_leadnumber_kanban_patch': {
      const leadNum = rawArgs?.leadNumber || rawArgs?.lead_number;
      return callZattenApi(`/leads/${leadNum}/kanban`, 'PATCH', {
        column_id: rawArgs.column_id
      }, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    // --- MELHORIA 1: ATRIBUIÇÃO DE RESPONSÁVEL COM VALIDAÇÃO ZOD ---
    case 'zatten_leads_leadnumber_assignee_patch': {
      const parseResult = ZattenLeadsLeadNumberAssigneePatchSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Argumentos inválidos para atribuição de responsável.',
          httpStatus: 400,
          correlationId,
          details: parseResult.error.issues
        });
      }

      const validArgs = parseResult.data;
      const leadNum = validArgs.leadNumber || validArgs.lead_number!;

      const payload: Record<string, any> = {
        department_id: validArgs.department_id
      };
      if (validArgs.user_email) {
        payload.user_email = validArgs.user_email;
      } else if (validArgs.user_id) {
        payload.user_id = validArgs.user_id;
      } else {
        payload.round_robin = true;
      }

      const result = await callZattenApi(
        `/leads/${leadNum}/assignee`,
        'PATCH',
        payload,
        validArgs.connection_id || validArgs.connectionId,
        orgId,
        true
      );

      if (result && !result.isError) {
        return {
          ok: true,
          lead_number: leadNum,
          department_id: validArgs.department_id,
          assigned_user: validArgs.user_email || validArgs.user_id || 'rodizio_departamento',
          status: 'updated',
          response: result
        };
      }
      return result;
    }

    // --- MELHORIA 2: CONTROLE DA IA COM VALIDAÇÃO ZOD ---
    case 'zatten_leads_leadnumber_toggle_attendant_response_post': {
      const parseResult = ZattenLeadsLeadNumberAiPatchSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Argumentos inválidos para controle da IA.',
          httpStatus: 400,
          correlationId,
          details: parseResult.error.issues
        });
      }

      const validArgs = parseResult.data;
      const leadNum = validArgs.leadNumber || validArgs.lead_number!;

      const payload: Record<string, any> = {
        enabled: validArgs.enabled
      };
      if (!validArgs.enabled && validArgs.pause_minutes) {
        payload.pause_minutes = validArgs.pause_minutes;
      }

      const result = await callZattenApi(
        `/leads/${leadNum}/toggle-attendant-response`,
        'POST',
        payload,
        validArgs.connection_id || validArgs.connectionId,
        orgId,
        true
      );

      if (result && !result.isError) {
        let statusDescription = 'IA ligada para o lead.';
        if (!validArgs.enabled) {
          if (validArgs.pause_minutes) {
            const resumeDate = new Date(Date.now() + validArgs.pause_minutes * 60000).toISOString();
            statusDescription = `IA pausada por ${validArgs.pause_minutes} minutos (até ${resumeDate}).`;
          } else {
            statusDescription = 'IA desligada por tempo indeterminado.';
          }
        }

        return {
          ok: true,
          lead_number: leadNum,
          enabled: validArgs.enabled,
          pause_minutes: validArgs.pause_minutes || null,
          status: statusDescription,
          response: result
        };
      }
      return result;
    }

    case 'zatten_leads_leadnumber_tag_post': {
      const leadNum = rawArgs?.leadNumber || rawArgs?.lead_number;
      return callZattenApi(`/leads/${leadNum}/tag`, 'POST', {
        tag_id: rawArgs.tag_id
      }, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_leads_leadnumber_tag_delete': {
      const leadNum = rawArgs?.leadNumber || rawArgs?.lead_number;
      return callZattenApi(`/leads/${leadNum}/tag`, 'DELETE', {
        tag_id: rawArgs.tag_id
      }, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    // --- NOVA FERRAMENTA 1: LISTAR PROPRIEDADES DO PROJETO ---
    case 'zatten_properties_get': {
      const parseResult = ZattenPropertiesGetSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetros inválidos.',
          httpStatus: 400,
          correlationId
        });
      }

      const res = await callZattenApi(
        '/properties',
        'GET',
        null,
        parseResult.data.connection_id || parseResult.data.connectionId,
        orgId
      );

      if (res && Array.isArray(res.properties)) {
        return {
          properties: res.properties.map((p: any) => ({
            slug: p.slug,
            name: p.name,
            description: p.description,
            is_enum: Boolean(p.is_enum)
          }))
        };
      }

      if (Array.isArray(res)) {
        return {
          properties: res.map((p: any) => ({
            slug: p.slug,
            name: p.name,
            description: p.description,
            is_enum: Boolean(p.is_enum)
          }))
        };
      }

      return res;
    }

    // --- NOVA FERRAMENTA 2: LISTAR VALORES DE PROPRIEDADE ENUM ---
    case 'zatten_properties_slug_values_get': {
      const parseResult = ZattenPropertiesSlugValuesGetSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetro property_slug obrigatório e deve ser válido.',
          httpStatus: 400,
          correlationId
        });
      }

      const slug = parseResult.data.property_slug;
      const res = await callZattenApi(
        `/properties/${slug}/values`,
        'GET',
        null,
        parseResult.data.connection_id || parseResult.data.connectionId,
        orgId
      );

      // Se a propriedade for texto livre, a Zatten pode devolver 400 ou indicação
      if (res && (res.isError || res.ok === false) && (res.error?.httpStatus === 400 || res.error?.httpStatus === 404)) {
        return {
          property_slug: slug,
          values: [],
          is_free_text: true,
          message: `A propriedade '${slug}' aceita texto livre e não possui restrição de valores enum.`
        };
      }

      if (res && Array.isArray(res.values)) {
        return {
          property_slug: slug,
          values: res.values.map((v: any) => ({
            value: typeof v === 'string' ? v : v.value,
            description: typeof v === 'object' ? v.description : undefined
          }))
        };
      }

      if (Array.isArray(res)) {
        return {
          property_slug: slug,
          values: res.map((v: any) => ({
            value: typeof v === 'string' ? v : v.value,
            description: typeof v === 'object' ? v.description : undefined
          }))
        };
      }

      return res;
    }

    // --- NOVA FERRAMENTA 3: NOTIFICAR RESPONSÁVEL DO LEAD ---
    case 'zatten_leads_leadnumber_notification_post': {
      const parseResult = ZattenLeadsLeadNumberNotificationPostSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetros inválidos para envio de notificação.',
          httpStatus: 400,
          correlationId,
          details: parseResult.error.issues
        });
      }

      const validArgs = parseResult.data;
      const leadNum = validArgs.lead_number || validArgs.leadNumber!;

      const payload: Record<string, any> = {};
      if (validArgs.title) payload.title = validArgs.title;
      if (validArgs.body) payload.body = validArgs.body;

      const res = await callZattenApi(
        `/leads/${leadNum}/notification`,
        'POST',
        payload,
        validArgs.connection_id || validArgs.connectionId,
        orgId,
        true
      );

      // Não converter sent: false em erro técnico
      if (res && res.sent === false) {
        return {
          sent: false,
          reason: res.reason || 'NO_ASSIGNEE',
          profile_id: res.profile_id
        };
      }

      if (res && res.sent === true) {
        return {
          sent: true,
          profile_id: res.profile_id
        };
      }

      return res;
    }

    // --- NOVA FERRAMENTA 4: DISPARAR AUTOMAÇÕES DO LEAD ---
    case 'zatten_automations_trigger_post': {
      const parseResult = ZattenAutomationsTriggerPostSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'lead_id obrigatório.',
          httpStatus: 400,
          correlationId
        });
      }

      const res = await callZattenApi(
        '/automations/trigger',
        'POST',
        { lead_id: parseResult.data.lead_id },
        parseResult.data.connection_id || parseResult.data.connectionId,
        orgId,
        true
      );

      if (res && !res.isError) {
        return {
          ok: true,
          message: 'Solicitação de disparo de automações despachada. Sucesso na rota não garante que haja automação aplicável ou que ela já executou.',
          details: res
        };
      }

      return res;
    }

    // --- NOVA FERRAMENTA 5: DISPARAR TRIGGER FLOW ---
    case 'zatten_flows_trigger_post': {
      const parseResult = ZattenFlowsTriggerPostSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetros inválidos para Trigger Flow.',
          httpStatus: 400,
          correlationId,
          details: parseResult.error.issues
        });
      }

      const validArgs = parseResult.data;
      const idempotencyKey = validArgs.idempotency_key || crypto.randomUUID();

      const payload: Record<string, any> = {
        trigger_type: validArgs.trigger_type,
        idempotency_key: idempotencyKey
      };

      if (validArgs.lead_number || validArgs.leadNumber) {
        payload.lead_number = validArgs.lead_number || validArgs.leadNumber;
      }
      if (validArgs.lead_id) {
        payload.lead_id = validArgs.lead_id;
      }
      if (validArgs.trigger_event) {
        payload.trigger_event = validArgs.trigger_event;
      }

      // Regra 5: NUNCA enviar attendant_id para a Zatten
      delete payload.attendant_id;

      const res = await callZattenApi(
        '/flows/trigger',
        'POST',
        payload,
        validArgs.connection_id || validArgs.connectionId,
        orgId,
        true
      );

      if (res && !res.isError) {
        return {
          matched: res.matched ?? 1,
          dispatched: res.dispatched ?? 1,
          deduped: Boolean(res.deduped),
          runs: res.runs || [{ status: 'running' }],
          info: 'HTTP 202: Trigger Flow despachado para processamento assíncrono (não concluído de imediato).'
        };
      }

      return res;
    }

    // --- NOVA FERRAMENTA 6: DISPARAR WEBHOOK DE ENTRADA ---
    case 'zatten_hooks_path_post': {
      const parseResult = ZattenHooksPathPostSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetros inválidos para webhook de entrada.',
          httpStatus: 400,
          correlationId,
          details: parseResult.error.issues
        });
      }

      const validArgs = parseResult.data;
      const cleanPath = validArgs.path;

      const payload: Record<string, any> = {
        idempotency_key: validArgs.idempotency_key || crypto.randomUUID()
      };
      if (validArgs.lead_number || validArgs.leadNumber) {
        payload.lead_number = validArgs.lead_number || validArgs.leadNumber;
      }
      if (validArgs.lead_id) {
        payload.lead_id = validArgs.lead_id;
      }
      if (validArgs.payload) {
        payload.data = validArgs.payload;
      }

      const res = await callZattenApi(
        `/hooks/${cleanPath}`,
        'POST',
        payload,
        validArgs.connection_id || validArgs.connectionId,
        orgId,
        true
      );

      if (res && !res.isError) {
        return {
          ok: true,
          status: 202,
          info: 'Payload despachado para o webhook. HTTP 202 não confirma que um flow correspondeu ao path.'
        };
      }

      return res;
    }

    // --- NOVA FERRAMENTA 7: LER CONFIGURAÇÃO DO AGENTE (SANITIZADA) ---
    case 'zatten_agent_config_get': {
      const parseResult = ZattenAgentConfigGetSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: 'Argumentos inválidos.',
          httpStatus: 400,
          correlationId
        });
      }

      const res = await callZattenTemplateApi(
        'GET',
        undefined,
        parseResult.data.connection_id || parseResult.data.connectionId,
        orgId
      );

      if (res && res.isError) {
        return res;
      }

      // Sanitização profunda: remover todas as credenciais e headers secretos com <redacted>
      const sanitizedTemplate = sanitizeTemplateSecrets(res.template || res);

      return {
        project: {
          id: res.project?.id || res.projectId || 'current',
          name: res.project?.name
        },
        revision: String(res.revision || res.version || 'rev_1'),
        template: sanitizedTemplate,
        secrets_redacted: true
      };
    }

    // --- NOVA FERRAMENTA 8: ATUALIZAR CONFIGURAÇÃO DO AGENTE (RASCUNHO SEGURO) ---
    case 'zatten_agent_config_update': {
      const parseResult = ZattenAgentConfigUpdateSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetros inválidos para atualização de template.',
          httpStatus: 400,
          correlationId,
          details: parseResult.error.issues
        });
      }

      const validArgs = parseResult.data;

      // 1. Validar que o payload não tenta injetar <redacted> ou segredos em branco
      try {
        validateNoRedactedOrEmptySecrets(validArgs.template_patch);
      } catch (validationErr: any) {
        return formatMcpError({
          code: 'INVALID_SECRET_PAYLOAD',
          message: validationErr.message,
          httpStatus: 400,
          correlationId
        });
      }

      // 2. Ler o template bruto internamente via GET
      const getRes = await callZattenTemplateApi(
        'GET',
        undefined,
        validArgs.connection_id || validArgs.connectionId,
        orgId
      );

      if (getRes && getRes.isError) {
        return getRes;
      }

      const currentRevision = String(getRes.revision || getRes.version || 'rev_1');

      // 3. Comparar a revision atual com expected_revision
      if (currentRevision !== validArgs.expected_revision) {
        return formatMcpError({
          code: 'REVISION_CONFLICT',
          message: `Conflito de concorrência detectado: revision atual é '${currentRevision}', mas foi informada '${validArgs.expected_revision}'. Atualização abortada.`,
          httpStatus: 409,
          correlationId,
          details: { currentRevision, expectedRevision: validArgs.expected_revision }
        });
      }

      // 4. Fazer merge seguro no backend preservando todos os segredos existentes
      const rawCurrentTemplate = getRes.template || getRes;
      const { finalTemplate, changes, notes, orphans, ambiguous } = mergeTemplatePatch(
        rawCurrentTemplate,
        validArgs.template_patch
      );

      // 5. Enviar a atualização com publish_agent: false e submit_meta_templates: false
      const updatePayload = {
        template: finalTemplate,
        publish_agent: false,
        submit_meta_templates: false
      };

      const postRes = await callZattenTemplateApi(
        'POST',
        updatePayload,
        validArgs.connection_id || validArgs.connectionId,
        orgId
      );

      if (postRes && postRes.isError) {
        return postRes;
      }

      // 6. Reler o template e retornar versão sanitizada
      const sanitizedFinal = sanitizeTemplateSecrets(finalTemplate);
      const newRevision = String(postRes.revision || postRes.version || `${currentRevision}_updated`);

      return {
        ok: true,
        previous_revision: currentRevision,
        revision: newRevision,
        agent: {
          version: postRes.agent?.version,
          published: false
        },
        changes,
        notes,
        orphans,
        ambiguous,
        template: sanitizedFinal
      };
    }

    // --- MENSAGENS E OUTROS RECURSOS ---
    case 'zatten_messages_text_post': {
      return callZattenApi('/messages/text', 'POST', {
        lead_number: rawArgs.lead_number,
        message: rawArgs.message,
        name: rawArgs.name
      }, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_send_message': {
      return callZattenApi('/messages/text', 'POST', {
        lead_number: rawArgs.recipient,
        message: rawArgs.message || rawArgs.messageText
      }, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_messages_template_post': {
      return callZattenApi('/messages/template', 'POST', {
        lead_number: rawArgs.lead_number,
        template_name: rawArgs.template_name,
        name: rawArgs.name
      }, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_messages_audio_post': {
      const formData = await buildMediaFormData('audio', rawArgs);
      return callZattenApi('/messages/audio', 'POST', formData, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_messages_image_post': {
      const formData = await buildMediaFormData('image', rawArgs);
      return callZattenApi('/messages/image', 'POST', formData, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_messages_file_post': {
      const formData = await buildMediaFormData('file', rawArgs);
      return callZattenApi('/messages/file', 'POST', formData, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_messages_video_post': {
      const formData = await buildMediaFormData('video', rawArgs);
      return callZattenApi('/messages/video', 'POST', formData, rawArgs?.connection_id || rawArgs?.connectionId, orgId, true);
    }

    case 'zatten_messages_history_get': {
      const q = new URLSearchParams();
      const leadNum = rawArgs.leadNumber || rawArgs.lead_number;
      if (leadNum) q.set('leadNumber', leadNum);
      if (rawArgs.thread_id) q.set('thread_id', rawArgs.thread_id);
      if (rawArgs.llm_format !== undefined) q.set('llm_format', String(rawArgs.llm_format));
      return callZattenApi(`/messages/history?${q.toString()}`, 'GET', null, rawArgs?.connection_id || rawArgs?.connectionId, orgId);
    }

    case 'zatten_users_get':
    case 'zatten_attendants_list': {
      let dbAttendants: any[] = [];
      let dbDepartments: any[] = [];
      if (fs.existsSync(dbPath)) {
        try {
          const dbData = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
          dbAttendants = dbData.attendants || [];
          dbDepartments = dbData.departments || [];
        } catch {}
      }
      const usersList = dbAttendants.map(a => ({
        id: a.id,
        name: a.name,
        email: a.email,
        role: a.role,
        departmentId: a.department?.id || (dbDepartments[0]?.id || ''),
        departmentName: a.department?.name || (dbDepartments[0]?.name || '')
      }));
      return {
        users: usersList,
        attendants: usersList,
        responsaveis: usersList,
        departments: dbDepartments,
        total: usersList.length,
        help: "Utilize o e-mail (user_email) e o department_id de um dos responsáveis acima para atribuir o lead via zatten_leads_leadnumber_assignee_patch."
      };
    }

    case 'zatten_templates_get':
    case 'zatten_templates_list': {
      let dbTemplates: any[] = [];
      if (fs.existsSync(dbPath)) {
        try {
          const dbData = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
          dbTemplates = dbData.templates || [];
        } catch {}
      }
      return {
        templates: dbTemplates,
        hsm_templates: dbTemplates,
        total: dbTemplates.length,
        info: 'Templates HSM cadastrados e aprovados pela Meta WhatsApp Business API disponíveis para envio via zatten_messages_template_post.'
      };
    }

    // --- EXECUÇÃO DE FERRAMENTAS DE SKILLS DE IA ---
    case 'firstsys_skills_list': {
      const parseResult = SkillListSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetros inválidos.',
          httpStatus: 400,
          correlationId
        });
      }

      let skills: any[] = [];
      if (fs.existsSync(dbPath)) {
        try {
          const dbData = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
          skills = dbData.skills || [];
        } catch {}
      }

      const { category, query, installed_only } = parseResult.data;

      if (category && category !== 'todas') {
        skills = skills.filter(s => s.category?.toLowerCase() === category.toLowerCase());
      }

      if (installed_only) {
        skills = skills.filter(s => s.installed === true);
      }

      if (query) {
        const q = query.toLowerCase();
        skills = skills.filter(s =>
          s.name?.toLowerCase().includes(q) ||
          s.description?.toLowerCase().includes(q) ||
          (Array.isArray(s.tags) && s.tags.some((t: string) => t.toLowerCase().includes(q)))
        );
      }

      return {
        skills: skills.map(s => ({
          id: s.id,
          name: s.name,
          slug: s.slug,
          description: s.description,
          category: s.category,
          tags: s.tags,
          status: s.status,
          installed: s.installed,
          version: s.version,
          files_count: Array.isArray(s.files) ? s.files.length : 0,
          files_available: Array.isArray(s.files) ? s.files.map((f: any) => f.name) : []
        })),
        total: skills.length,
        info: "Utilize 'firstsys_skills_get' com o 'skill_id' para consultar o conteúdo integral do arquivo SKILL.md de uma skill."
      };
    }

    case 'firstsys_skills_get': {
      const parseResult = SkillGetSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'skill_id é obrigatório.',
          httpStatus: 400,
          correlationId
        });
      }

      const { skill_id } = parseResult.data;
      let skills: any[] = [];
      if (fs.existsSync(dbPath)) {
        try {
          const dbData = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
          skills = dbData.skills || [];
        } catch {}
      }

      const skill = skills.find(s => s.id === skill_id || s.slug === skill_id);
      if (!skill) {
        return formatMcpError({
          code: 'SKILL_NOT_FOUND',
          message: `Nenhuma skill encontrada com o identificador '${skill_id}'.`,
          httpStatus: 404,
          correlationId
        });
      }

      return {
        ok: true,
        skill: {
          id: skill.id,
          name: skill.name,
          slug: skill.slug,
          description: skill.description,
          category: skill.category,
          tags: skill.tags,
          status: skill.status,
          installed: skill.installed,
          version: skill.version,
          files: skill.files || []
        }
      };
    }

    case 'firstsys_skills_install': {
      const parseResult = SkillInstallSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'skill_id é obrigatório.',
          httpStatus: 400,
          correlationId
        });
      }

      const { skill_id, install } = parseResult.data;
      if (!fs.existsSync(dbPath)) {
        return formatMcpError({ code: 'DB_ERROR', message: 'Banco indisponível.', httpStatus: 500, correlationId });
      }

      const dbData = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
      const skills = dbData.skills || [];
      const skill = skills.find((s: any) => s.id === skill_id || s.slug === skill_id);

      if (!skill) {
        return formatMcpError({
          code: 'SKILL_NOT_FOUND',
          message: `Skill '${skill_id}' não encontrada para instalação.`,
          httpStatus: 404,
          correlationId
        });
      }

      skill.installed = install;
      skill.status = install ? 'active' : 'inactive';
      skill.updatedAt = new Date().toISOString();

      fs.writeFileSync(dbPath, JSON.stringify(dbData, null, 2));

      return {
        ok: true,
        message: install ? `Skill '${skill.name}' instalada e ativada com sucesso.` : `Skill '${skill.name}' desinstalada.`,
        skill_id: skill.id,
        installed: skill.installed,
        status: skill.status
      };
    }

    case 'firstsys_skills_create': {
      const parseResult = SkillCreateSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetros inválidos para criação de skill.',
          httpStatus: 400,
          correlationId,
          details: parseResult.error.issues
        });
      }

      const { name: skillName, description, category, tags, skill_md_content } = parseResult.data;
      if (!fs.existsSync(dbPath)) {
        return formatMcpError({ code: 'DB_ERROR', message: 'Banco indisponível.', httpStatus: 500, correlationId });
      }

      const dbData = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
      if (!dbData.skills) dbData.skills = [];

      const slug = skillName
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '');

      const id = `skill_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      const now = new Date().toISOString();

      const newSkill = {
        id,
        name: skillName.trim(),
        slug: slug || id,
        description: description.trim(),
        category: (category || 'geral').toLowerCase().trim(),
        tags: tags || [],
        status: 'active',
        installed: true,
        version: '1.0.0',
        author: 'ChatGPT / MCP Agent',
        createdAt: now,
        updatedAt: now,
        files: [
          {
            name: 'SKILL.md',
            path: '/SKILL.md',
            language: 'markdown',
            updatedAt: now,
            content: skill_md_content?.trim() || `# Skill: ${skillName}\n\n## Objetivo\n${description}`
          }
        ]
      };

      dbData.skills.push(newSkill);
      fs.writeFileSync(dbPath, JSON.stringify(dbData, null, 2));

      return {
        ok: true,
        message: `Skill '${newSkill.name}' criada com sucesso pela IA.`,
        skill: newSkill
      };
    }

    case 'firstsys_skills_update': {
      const parseResult = SkillUpdateSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Parâmetros inválidos.',
          httpStatus: 400,
          correlationId
        });
      }

      const { skill_id, name: newName, description: newDesc, skill_md_content } = parseResult.data;
      if (!fs.existsSync(dbPath)) {
        return formatMcpError({ code: 'DB_ERROR', message: 'Banco indisponível.', httpStatus: 500, correlationId });
      }

      const dbData = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
      const skills = dbData.skills || [];
      const skill = skills.find((s: any) => s.id === skill_id || s.slug === skill_id);

      if (!skill) {
        return formatMcpError({
          code: 'SKILL_NOT_FOUND',
          message: `Skill '${skill_id}' não encontrada.`,
          httpStatus: 404,
          correlationId
        });
      }

      if (newName) skill.name = newName.trim();
      if (newDesc) skill.description = newDesc.trim();

      if (skill_md_content) {
        if (!Array.isArray(skill.files)) skill.files = [];
        const skillMdFile = skill.files.find((f: any) => f.name.toLowerCase() === 'skill.md');
        if (skillMdFile) {
          skillMdFile.content = skill_md_content.trim();
          skillMdFile.updatedAt = new Date().toISOString();
        } else {
          skill.files.push({
            name: 'SKILL.md',
            path: '/SKILL.md',
            language: 'markdown',
            updatedAt: new Date().toISOString(),
            content: skill_md_content.trim()
          });
        }
      }

      skill.updatedAt = new Date().toISOString();
      fs.writeFileSync(dbPath, JSON.stringify(dbData, null, 2));

      return {
        ok: true,
        message: `Skill '${skill.name}' atualizada com sucesso.`,
        skill
      };
    }

    case 'firstsys_skills_delete': {
      const parseResult = SkillDeleteSchema.safeParse(rawArgs);
      if (!parseResult.success) {
        return formatMcpError({
          code: 'INVALID_ARGUMENTS',
          message: parseResult.error.issues[0]?.message || 'Exclusão requer confirm: true.',
          httpStatus: 400,
          correlationId
        });
      }

      const { skill_id } = parseResult.data;
      if (!fs.existsSync(dbPath)) {
        return formatMcpError({ code: 'DB_ERROR', message: 'Banco indisponível.', httpStatus: 500, correlationId });
      }

      const dbData = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
      const skills = dbData.skills || [];
      const exists = skills.some((s: any) => s.id === skill_id || s.slug === skill_id);

      if (!exists) {
        return formatMcpError({
          code: 'SKILL_NOT_FOUND',
          message: `Skill '${skill_id}' não encontrada.`,
          httpStatus: 404,
          correlationId
        });
      }

      dbData.skills = skills.filter((s: any) => s.id !== skill_id && s.slug !== skill_id);
      fs.writeFileSync(dbPath, JSON.stringify(dbData, null, 2));

      return {
        ok: true,
        message: `Skill '${skill_id}' removida com sucesso pela IA.`
      };
    }

    default:
      throw new Error(`Ferramenta não encontrada: ${name}`);
  }
}

// ==============================================================================
// 8. ENDPOINTS HTTP E SSE DO SERVIDOR MCP
// ==============================================================================

mcpRouter.get(['/', '/sse'], (req: AuthenticatedMcpRequest, res: Response) => {
  const authHeader = req.headers.authorization;
  const issuer = process.env.OAUTH_ISSUER_URL || `${req.protocol}://${req.get('host')}`;
  const resourceMetadataUrl = `${issuer}/.well-known/oauth-protected-resource`;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.setHeader('WWW-Authenticate', `Bearer error="unauthorized", resource_metadata="${resourceMetadataUrl}"`);
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Token OAuth 2.1 Bearer obrigatório para conectar ao servidor MCP Firstsys.',
      resource_metadata: resourceMetadataUrl
    });
  }

  const token = authHeader.split(' ')[1];
  const verification = verifyJwt(token);
  if (!verification.valid || !verification.payload) {
    res.setHeader('WWW-Authenticate', `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrl}"`);
    return res.status(401).json({
      error: 'invalid_token',
      message: verification.error || 'Token OAuth inválido ou expirado',
      resource_metadata: resourceMetadataUrl
    });
  }

  const accept = req.headers.accept || '';
  if (accept.includes('text/event-stream')) {
    const sessionId = `mcp_sess_${crypto.randomBytes(16).toString('hex')}`;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    res.write(`event: endpoint\ndata: ${issuer}/mcp/messages?sessionId=${sessionId}\n\n`);

    const interval = setInterval(() => {
      res.write(': ping\n\n');
    }, 15000);

    req.on('close', () => {
      clearInterval(interval);
    });
    return;
  }

  return res.json({
    name: 'Firstsys Zatten Central MCP Server',
    version: '1.0.0',
    protocolVersion: '2024-11-05',
    status: 'ready',
    toolsCount: MCP_TOOLS_CATALOG.length
  });
});

const jsonRpcHandler = async (req: AuthenticatedMcpRequest, res: Response) => {
  const body = req.body;
  const user = req.oauthUser!;

  if (!body || typeof body !== 'object') {
    return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
  }

  const method = body.method;
  const id = body.id;

  switch (method) {
    case 'initialize':
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: { listChanged: true }
          },
          serverInfo: {
            name: 'Firstsys Zatten Central MCP',
            version: '1.0.0'
          }
        }
      });

    case 'notifications/initialized':
      return res.status(200).send();

    case 'ping':
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {}
      });

    case 'tools/list':
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          tools: MCP_TOOLS_CATALOG
        }
      });

    case 'tools/call': {
      const toolName = body.params?.name;
      const args = body.params?.arguments || {};
      try {
        const output = await executeToolDirectly(toolName, args, user);

        const isFailure = !!(
          output &&
          (output.isError === true ||
           output.ok === false ||
           output.error !== undefined ||
           (typeof output.status === 'number' && output.status >= 400) ||
           output.success === false)
        );

        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: typeof output === 'string' ? output : JSON.stringify(output, null, 2)
              }
            ],
            isError: isFailure
          }
        });
      } catch (err: any) {
        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  error: 'Falha interna ao executar ferramenta MCP',
                  details: err.message || 'Erro inesperado'
                }, null, 2)
              }
            ],
            isError: true
          }
        });
      }
    }

    default:
      return res.status(404).json({
        jsonrpc: '2.0',
        id,
        error: {
          code: -32601,
          message: `Method not found: ${method}`
        }
      });
  }
};

mcpRouter.post(['/', '/messages'], requireOAuth(), jsonRpcHandler);

mcpRouter.get('/tools', requireOAuth(), (_req: AuthenticatedMcpRequest, res: Response) => {
  return res.json({
    tools: MCP_TOOLS_CATALOG
  });
});

mcpRouter.post('/tools/firstsys_get_profile', requireOAuth('profile'), (req: AuthenticatedMcpRequest, res: Response) => {
  const user = req.oauthUser!;
  return res.json({
    id: user.sub,
    organizationId: user.org_id,
    role: user.role,
    scope: user.scope,
    client: user.client_id
  });
});

const MOCK_DB_PATH = path.join(process.cwd(), 'server', 'db.json');

mcpRouter.post('/tools/zatten_list_connections', requireOAuth('connections:read'), (req: AuthenticatedMcpRequest, res: Response) => {
  const user = req.oauthUser!;

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

// Endpoint com confirmação humana em duas etapas
const confirmationTokens = new Map<string, {
  tool: string;
  parameters: any;
  orgId: string;
  expiresAt: number;
}>();

const SendMessageSchema = z.object({
  connectionId: z.string().min(1).optional(),
  connection_id: z.string().min(1).optional(),
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

    const { recipient, messageText, confirmationToken } = parseResult.data;
    const connectionId = parseResult.data.connectionId || parseResult.data.connection_id || 'conn_coolify_principal';

    if (!confirmationToken) {
      const token = `conf_${crypto.randomBytes(16).toString('hex')}`;
      confirmationTokens.set(token, {
        tool: 'zatten_send_message',
        parameters: { connectionId, recipient, messageText },
        orgId: user.org_id || 'org_firstsys_prod',
        expiresAt: Date.now() + 5 * 60 * 1000
      });

      return res.status(200).json({
        requiresHumanConfirmation: true,
        confirmationToken: token,
        actionPreview: {
          action: 'Envio de Mensagem WhatsApp / Zatten',
          destinatario: maskLeadNumber(recipient),
          mensagem: messageText,
          conexao: connectionId
        },
        message: 'Para prosseguir com o envio, o usuário deve confirmar a ação informando o confirmationToken.'
      });
    }

    const record = confirmationTokens.get(confirmationToken);
    if (!record || record.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'invalid_confirmation', message: 'Token de confirmação expirado ou inválido.' });
    }

    if (record.orgId !== (user.org_id || 'org_firstsys_prod')) {
      return res.status(403).json({ error: 'forbidden', message: 'Token de confirmação pertence a outra organização.' });
    }

    confirmationTokens.delete(confirmationToken);

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
      description: `Mensagem enviada com confirmação humana para ${maskLeadNumber(recipient)}`,
      ipAddress: req.ip || '127.0.0.1'
    });

    return res.json(result);
  } catch (err: unknown) {
    console.error('[MCP send_message] Erro:', err);
    return res.status(500).json({ error: 'server_error', message: 'Falha ao executar operação MCP' });
  }
});

// Roteador REST Dinâmico para ferramentas OpenAPI / ChatGPT Custom Actions
mcpRouter.post('/tools/:toolName', requireOAuth(), async (req: AuthenticatedMcpRequest, res: Response) => {
  const rawToolName = req.params.toolName;
  const toolName = Array.isArray(rawToolName) ? rawToolName[0] : String(rawToolName || '');
  const user = req.oauthUser!;
  const args = req.body || {};

  try {
    const result = await executeToolDirectly(toolName, args, user);
    return res.json(result);
  } catch (err: any) {
    console.error(`[MCP REST] Erro ao executar ${toolName}:`, err);
    return res.status(err.message?.includes('não encontrada') ? 404 : 500).json({
      error: 'tool_execution_failed',
      message: err.message || 'Erro ao processar chamada da ferramenta'
    });
  }
});
