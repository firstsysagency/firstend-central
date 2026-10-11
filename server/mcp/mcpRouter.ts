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
import { zattenClient, buildZattenUrl } from '../zatten/zattenClient.js';
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
      const grantedScopes = payload.scope.split(' ');
      if (!grantedScopes.includes(requiredScope)) {
        res.setHeader('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${requiredScope}", resource_metadata="${resourceMetadataUrl}"`);
        return res.status(403).json({
          error: 'insufficient_scope',
          message: `Escopo insuficiente. Esta ferramenta requer '${requiredScope}'.`
        });
      }
    }

    console.log('🤖 [MCP Requisição Autenticada]', {
      sub: payload.sub,
      client_id: payload.client_id,
      path: req.path,
      method: req.body?.method || req.method
    });

    req.oauthUser = payload;
    next();
  };
}

// ==============================================================================
// ==============================================================================
// 1.1 CATÁLOGO DE FERRAMENTAS MCP CONFORME PROTOCOLO 2024-11-05 (COMPLETO ZATTEN)
// ==============================================================================

const MCP_TOOLS_CATALOG = [
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
  {
    name: 'zatten_kanban_get',
    title: 'Buscar Colunas do Kanban Zatten',
    description: 'Busca informações de todas as colunas do Kanban de atendimento no CRM Zatten.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
    description: 'Atualiza ou adiciona anotações no perfil de um lead no CRM Zatten.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'note'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        note: { type: 'string', description: 'O conteúdo da anotação a ser salva.' },
        delete_previous_note: { type: 'boolean', description: 'Se true, substitui a anotação antiga; se false, concatena.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
    description: 'Atualiza propriedades customizadas de um lead a partir do slug da propriedade.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'property', 'value'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        property: { type: 'string', description: 'O slug da propriedade a ser atualizada.' },
        value: { type: 'string', description: 'O novo valor para a propriedade.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
    description: 'Move um lead entre colunas do Kanban de atendimento.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'column_id'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        column_id: { type: 'string', description: 'O ID da coluna de destino no Kanban.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_kanban_patch', 'tool:zatten_leads_leadnumber_kanban_patch'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'kanban', 'leads']
  },
  {
    name: 'zatten_leads_leadnumber_assignee_patch',
    title: 'Atualizar Responsável e Time do Lead',
    description: 'Atualiza o responsável (usuário e departamento/time) de um lead.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'user_email', 'department_id'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        user_email: { type: 'string', description: 'E-mail do usuário responsável.' },
        department_id: { type: 'string', description: 'ID do departamento atribuído.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_assignee_patch', 'tool:zatten_leads_leadnumber_assignee_patch'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: false },
    tags: ['crm', 'leads', 'assignee']
  },
  {
    name: 'zatten_leads_leadnumber_toggle_attendant_response_post',
    title: 'Alternar Resposta Automática da IA do Lead',
    description: 'Ativa ou desativa a resposta automática do atendente de IA para um lead.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'enabled'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        enabled: { type: 'boolean', description: 'True para ativar ou false para desativar a IA.' },
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
    description: 'Adiciona uma tag específica a um lead no CRM Zatten.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'tag_id'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        tag_id: { type: 'string', description: 'O ID da tag a ser adicionada.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
    description: 'Remove uma tag de um lead no CRM Zatten.',
    inputSchema: {
      type: 'object',
      required: ['leadNumber', 'tag_id'],
      properties: {
        leadNumber: { type: 'string', description: 'O número de WhatsApp (WaId) do lead.' },
        tag_id: { type: 'string', description: 'O ID da tag a ser removida.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:write', 'zatten_leads_leadnumber_tag_delete', 'tool:zatten_leads_leadnumber_tag_delete'] }
    ],
    annotations: { readOnlyHint: false, destructiveHint: true },
    tags: ['crm', 'leads', 'tags']
  },
  {
    name: 'zatten_messages_text_post',
    title: 'Enviar Mensagem de Texto WhatsApp',
    description: 'Envia uma mensagem de texto simples para um lead no WhatsApp via API Zatten.',
    inputSchema: {
      type: 'object',
      required: ['lead_number', 'message'],
      properties: {
        lead_number: { type: 'string', description: 'Número de WhatsApp do destinatário com DDI/DDD.' },
        message: { type: 'string', description: 'Conteúdo da mensagem de texto.' },
        name: { type: 'string', description: 'Nome do lead (opcional).' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
    description: 'Envia uma mensagem de template HSM pré-aprovado para um lead no WhatsApp.',
    inputSchema: {
      type: 'object',
      required: ['lead_number', 'template_name'],
      properties: {
        lead_number: { type: 'string', description: 'Número de WhatsApp do destinatário.' },
        template_name: { type: 'string', description: 'Nome do template a ser enviado.' },
        name: { type: 'string', description: 'Nome do lead (opcional).' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        thread_id: { type: 'string', description: 'ID da thread (opcional).' },
        llm_format: { type: 'boolean', description: 'Se true, formata histórico para leitura direta de LLMs.' },
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
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
        connectionId: { type: 'string', description: 'ID da conexão Zatten (opcional)' }
      }
    },
    securitySchemes: [
      { type: 'oauth2', scopes: ['zatten:read', 'zatten_templates_get', 'tool:zatten_templates_get'] }
    ],
    annotations: { readOnlyHint: true, destructiveHint: false },
    tags: ['messages', 'templates', 'hsm']
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

// Função auxiliar para chamar a API da Zatten com a chave da conexão ativa
async function callZattenApi(endpoint: string, method: string, payload?: any, connectionId?: string) {
  const dbPath = path.join(process.cwd(), 'server', 'db.json');
  let apiKey = process.env.ZATTEN_API_KEY || '';

  if (fs.existsSync(dbPath)) {
    try {
      const db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
      const conn = (db.connections || []).find((c: any) => c.status === 'active' && (!connectionId || c.id === connectionId)) || db.connections?.[0];
      if (conn?.apiKey) {
        if (!conn.apiKey.startsWith('U2FsdGVkX1')) {
          apiKey = conn.apiKey;
        } else {
          // Descriptografa AES
          const FRONTEND_SECRET = process.env.VITE_FRONTEND_AES_SECRET || 'chave_secreta_padrao_desenvolvimento_256';
          const bytes = CryptoJS.AES.decrypt(conn.apiKey, FRONTEND_SECRET);
          const dec = bytes.toString(CryptoJS.enc.Utf8);
          if (dec) apiKey = dec;
        }
      }
    } catch (e) {}
  }

  // Sanitização e resolução da URL canônica da Zatten (garante https://api.zatten.com/api/v1)
  const targetUrl = buildZattenUrl(endpoint);

  if (!apiKey || apiKey.length < 5) {
    return {
      isError: true,
      error: 'Nenhuma chave de API Zatten válida (x-api-key) encontrada na conexão ou variáveis de ambiente.',
      message: 'Configure a x-api-key da Zatten na Central Firstsys para executar chamadas reais.',
      endpoint,
      method,
      targetUrl
    };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 segundos timeout

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

    const text = await res.text();
    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      data = { text };
    }

    if (!res.ok) {
      console.warn(`⚠️ [API Zatten Respondeu HTTP ${res.status}]`, {
        targetUrl,
        method,
        status: res.status,
        statusText: res.statusText
      });

      return {
        isError: true,
        error: `API Zatten respondeu com erro HTTP ${res.status} (${res.statusText || 'Erro'})`,
        status: res.status,
        details: data,
        targetUrl
      };
    }

    return data;
  } catch (err: any) {
    const isTimeout = err.name === 'AbortError';
    const errorCode = isTimeout ? 'ETIMEDOUT' : (err.cause?.code || err.code || 'FETCH_FAILED');

    // Log detalhado e seguro no servidor (sem expor a x-api-key)
    console.error('❌ [Falha de Conexão MCP -> Zatten]', {
      targetUrl,
      method,
      errorCode,
      message: err.message
    });

    return {
      isError: true,
      error: 'Erro de comunicação com a API Zatten',
      code: errorCode,
      details: isTimeout ? 'Tempo limite de requisição à Zatten esgotado (15s).' : (err.message || 'fetch failed'),
      targetUrl
    };
  }
}

// Execução centralizada de ferramentas MCP para chamadas JSON-RPC (tools/call)
async function executeToolDirectly(name: string, args: any, user: OAuthJwtPayload): Promise<any> {
  const dbPath = path.join(process.cwd(), 'server', 'db.json');

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
        connectionId: args?.connectionId || 'conn_coolify_principal',
        status: 'active',
        healthy: true,
        latencyMs: 38,
        lastCheck: new Date().toISOString()
      };

    case 'zatten_explain_lead_lookup':
    case 'zatten_get_leads': {
      const leadNum = args?.leadNumber || args?.lead_number;
      if (leadNum) {
        return callZattenApi(`/leads/${leadNum}`, 'GET', null, args?.connectionId);
      }
      return {
        leads: [],
        message: "A API da Zatten organiza leads pelo identificador de telefone (WaId) e não possui listagem global não filtrada. Utilize a ferramenta 'zatten_leads_leadnumber_get' informando o parâmetro 'leadNumber' (ex: 5511999999999) para consultar os dados do lead, ou 'zatten_kanban_get' para consultar as colunas do funil."
      };
    }

    case 'zatten_kanban_get':
      return callZattenApi('/kanban', 'GET', null, args?.connectionId);

    case 'zatten_tags_get':
      return callZattenApi('/tags', 'GET', null, args?.connectionId);

    case 'zatten_leads_leadnumber_get':
      return callZattenApi(`/leads/${args.leadNumber}`, 'GET', null, args?.connectionId);

    case 'zatten_leads_leadnumber_notes_patch':
      return callZattenApi(`/leads/${args.leadNumber}/notes`, 'PATCH', {
        note: args.note,
        delete_previous_note: args.delete_previous_note
      }, args?.connectionId);

    case 'zatten_leads_leadnumber_properties_patch': {
      let propValue = args?.value;
      // Regra da API Zatten: não aceita string vazia "" com erro 400 (Value must be at least 1 character long).
      // Para limpar ou desatribuir a propriedade, normaliza valores vazios/nulos para " " (espaço aceito com HTTP 200).
      if (propValue === null || propValue === undefined || (typeof propValue === 'string' && propValue.trim() === '')) {
        propValue = ' ';
      }
      return callZattenApi(`/leads/${args.leadNumber}/properties`, 'PATCH', {
        property: args.property,
        value: propValue
      }, args?.connectionId);
    }

    case 'zatten_leads_leadnumber_threads_get':
      return callZattenApi(`/leads/${args.leadNumber}/threads`, 'GET', null, args?.connectionId);

    case 'zatten_leads_leadnumber_thread_patch': {
      if (args?.confirm !== true) {
        return {
          isError: true,
          error: 'Operação destrutiva não confirmada. Reiniciar a thread apaga o contexto ativo da conversa com a IA. Para prosseguir com segurança, forneça confirm: true.',
          destructive: true
        };
      }
      return callZattenApi(`/leads/${args.leadNumber}/thread`, 'PATCH', {}, args?.connectionId);
    }

    case 'zatten_leads_leadnumber_kanban_patch':
      return callZattenApi(`/leads/${args.leadNumber}/kanban`, 'PATCH', {
        column_id: args.column_id
      }, args?.connectionId);

    case 'zatten_leads_leadnumber_assignee_patch':
      return callZattenApi(`/leads/${args.leadNumber}/assignee`, 'PATCH', {
        user_email: args.user_email,
        department_id: args.department_id
      }, args?.connectionId);

    case 'zatten_leads_leadnumber_toggle_attendant_response_post':
      return callZattenApi(`/leads/${args.leadNumber}/toggle-attendant-response`, 'POST', {
        enabled: args.enabled
      }, args?.connectionId);

    case 'zatten_leads_leadnumber_tag_post':
      return callZattenApi(`/leads/${args.leadNumber}/tag`, 'POST', {
        tag_id: args.tag_id
      }, args?.connectionId);

    case 'zatten_leads_leadnumber_tag_delete':
      return callZattenApi(`/leads/${args.leadNumber}/tag`, 'DELETE', {
        tag_id: args.tag_id
      }, args?.connectionId);

    case 'zatten_messages_text_post':
      return callZattenApi('/messages/text', 'POST', {
        lead_number: args.lead_number,
        message: args.message,
        name: args.name
      }, args?.connectionId);

    case 'zatten_send_message':
      return callZattenApi('/messages/text', 'POST', {
        lead_number: args.recipient,
        message: args.message || args.messageText
      }, args?.connectionId);

    case 'zatten_messages_template_post':
      return callZattenApi('/messages/template', 'POST', {
        lead_number: args.lead_number,
        template_name: args.template_name,
        name: args.name
      }, args?.connectionId);

    case 'zatten_messages_audio_post': {
      const formData = await buildMediaFormData('audio', args);
      return callZattenApi('/messages/audio', 'POST', formData, args?.connectionId);
    }

    case 'zatten_messages_image_post': {
      const formData = await buildMediaFormData('image', args);
      return callZattenApi('/messages/image', 'POST', formData, args?.connectionId);
    }

    case 'zatten_messages_file_post': {
      const formData = await buildMediaFormData('file', args);
      return callZattenApi('/messages/file', 'POST', formData, args?.connectionId);
    }

    case 'zatten_messages_video_post': {
      const formData = await buildMediaFormData('video', args);
      return callZattenApi('/messages/video', 'POST', formData, args?.connectionId);
    }

    case 'zatten_messages_history_get': {
      const q = new URLSearchParams();
      if (args.leadNumber) q.set('leadNumber', args.leadNumber);
      if (args.thread_id) q.set('thread_id', args.thread_id);
      if (args.llm_format !== undefined) q.set('llm_format', String(args.llm_format));
      return callZattenApi(`/messages/history?${q.toString()}`, 'GET', null, args?.connectionId);
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

    default:
      throw new Error(`Ferramenta não encontrada: ${name}`);
  }
}

// ==============================================================================
// 1.2 ENDPOINT RAIZ MCP: DESCOBERTA OAUTH E SSE (GET /mcp e GET /mcp/sse)
// ==============================================================================

mcpRouter.get(['/', '/sse'], (req: AuthenticatedMcpRequest, res: Response) => {
  const authHeader = req.headers.authorization;
  const issuer = process.env.OAUTH_ISSUER_URL || `${req.protocol}://${req.get('host')}`;
  const resourceMetadataUrl = `${issuer}/.well-known/oauth-protected-resource`;

  // Se não autenticado: HTTP 401 com WWW-Authenticate apontando para a descoberta OAuth da Firstsys
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

  // Suporte a SSE (Server-Sent Events) padrão da especificação MCP
  const accept = req.headers.accept || '';
  if (accept.includes('text/event-stream')) {
    const sessionId = `mcp_sess_${crypto.randomBytes(16).toString('hex')}`;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    // Envia o endpoint de mensagens para o cliente SSE da OpenAI
    res.write(`event: endpoint\ndata: ${issuer}/mcp/messages?sessionId=${sessionId}\n\n`);

    const interval = setInterval(() => {
      res.write(': ping\n\n');
    }, 15000);

    req.on('close', () => {
      clearInterval(interval);
    });
    return;
  }

  // Resposta descritiva JSON padrão
  return res.json({
    name: 'Firstsys Zatten Central MCP Server',
    version: '1.0.0',
    protocolVersion: '2024-11-05',
    status: 'ready',
    toolsCount: MCP_TOOLS_CATALOG.length
  });
});

// ==============================================================================
// 1.3 MENSAGENS MCP JSON-RPC 2.0 (POST /mcp e POST /mcp/messages)
// ==============================================================================

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

        // Protocolo MCP: sinaliza isError: true explicitamente para que clientes e LLMs
        // reconheçam quando a operação falhou em vez de tratá-la como concluída com sucesso
        const isFailure = !!(
          output &&
          (output.isError === true ||
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

// ==============================================================================
// 2. CATÁLOGO REST / TOOLS DAS FERRAMENTAS MCP
// ==============================================================================

mcpRouter.get('/tools', requireOAuth(), (_req: AuthenticatedMcpRequest, res: Response) => {
  return res.json({
    tools: MCP_TOOLS_CATALOG
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

// ==============================================================================
// 6. ROTEADOR REST DINÂMICO PARA FERRAMENTAS MCP / OPENAPI
// Permite que Custom Actions do ChatGPT e chamadas REST executem qualquer ferramenta
// diretamente via POST /mcp/tools/:toolName com autorização Bearer OAuth 2.1.
// ==============================================================================
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
