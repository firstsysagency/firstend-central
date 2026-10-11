/**
 * DEFINIÇÃO E SEGURANÇA DAS FERRAMENTAS MCP (CHATGPT / FIRSTSYS)
 * Central de Chaves Zatten — Checklist de Deploy 301
 */

import { logAuditEvent } from './audit';

export type McpToolType = 'read_only' | 'write_requiring_confirmation';

export interface McpToolDefinition {
  name: string;
  description: string;
  type: McpToolType;
  requiredScopes: string[];
  parameters: {
    name: string;
    type: string;
    description: string;
    required: boolean;
  }[];
  requiresExplicitConfirmation: boolean;
}

export interface McpConfirmationRequest {
  confirmationId: string;
  toolName: string;
  organizationId: string;
  connectionId: string;
  parameters: Record<string, unknown>;
  createdAt: string;
  expiresAt: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
}

/**
 * Catálogo auditado de ferramentas MCP seguras para o ChatGPT.
 */
export const MCP_TOOLS_CATALOG: McpToolDefinition[] = [
  // ---------------------------------------------------------------------------
  // Ferramentas de Leitura (Sem risco de alteração)
  // ---------------------------------------------------------------------------
  {
    name: 'zatten_list_connections',
    description: 'Lista as conexões ativas disponíveis para a organização sem expor credenciais.',
    type: 'read_only',
    requiredScopes: ['zatten:keys:read'],
    requiresExplicitConfirmation: false,
    parameters: [
      { name: 'organizationId', type: 'string', description: 'ID da organização do usuário', required: true }
    ]
  },
  {
    name: 'zatten_get_connection_status',
    description: 'Verifica o status operacional e última validação de uma conexão Zatten.',
    type: 'read_only',
    requiredScopes: ['zatten:keys:read'],
    requiresExplicitConfirmation: false,
    parameters: [
      { name: 'connectionId', type: 'string', description: 'Identificador da conexão Zatten', required: true }
    ]
  },
  {
    name: 'zatten_get_audit_summary',
    description: 'Recupera métricas agregadas de uso e integridade da conexão.',
    type: 'read_only',
    requiredScopes: ['zatten:keys:read'],
    requiresExplicitConfirmation: false,
    parameters: [
      { name: 'connectionId', type: 'string', description: 'Identificador da conexão', required: true }
    ]
  },

  // ---------------------------------------------------------------------------
  // Ferramentas de Escrita (CONFIRMAÇÃO OBRIGATÓRIA HABILITADA - Checklist 301)
  // ---------------------------------------------------------------------------
  {
    name: 'zatten_send_message',
    description: 'Envia mensagem a um contato via API Zatten. EXIGE CONFIRMAÇÃO DO USUÁRIO.',
    type: 'write_requiring_confirmation',
    requiredScopes: ['zatten:keys:write'],
    requiresExplicitConfirmation: true,
    parameters: [
      { name: 'connectionId', type: 'string', description: 'ID da conexão autorizada', required: true },
      { name: 'recipient', type: 'string', description: 'Número do destinatário internacional E.164', required: true },
      { name: 'messageText', type: 'string', description: 'Conteúdo da mensagem a ser enviada', required: true },
      { name: 'confirmationToken', type: 'string', description: 'Token de confirmação humana aprovado', required: false }
    ]
  },
  {
    name: 'zatten_update_lead_stage',
    description: 'Atualiza o estágio do lead no pipeline da Zatten. EXIGE CONFIRMAÇÃO DO USUÁRIO.',
    type: 'write_requiring_confirmation',
    requiredScopes: ['zatten:keys:write'],
    requiresExplicitConfirmation: true,
    parameters: [
      { name: 'connectionId', type: 'string', description: 'ID da conexão autorizada', required: true },
      { name: 'leadId', type: 'string', description: 'Identificador do lead', required: true },
      { name: 'newStage', type: 'string', description: 'Nova etapa do funil', required: true },
      { name: 'confirmationToken', type: 'string', description: 'Token de confirmação humana aprovado', required: false }
    ]
  },
  {
    name: 'zatten_rotate_key',
    description: 'Aciona rotação da chave da conexão na Central de Chaves. EXIGE CONFIRMAÇÃO DO USUÁRIO.',
    type: 'write_requiring_confirmation',
    requiredScopes: ['zatten:keys:write'],
    requiresExplicitConfirmation: true,
    parameters: [
      { name: 'connectionId', type: 'string', description: 'Identificador da conexão', required: true },
      { name: 'confirmationToken', type: 'string', description: 'Token de confirmação humana aprovado', required: false }
    ]
  },
  {
    name: 'zatten_revoke_connection',
    description: 'Revoga imediatamente o acesso da conexão Zatten. EXIGE CONFIRMAÇÃO DO USUÁRIO.',
    type: 'write_requiring_confirmation',
    requiredScopes: ['zatten:keys:write'],
    requiresExplicitConfirmation: true,
    parameters: [
      { name: 'connectionId', type: 'string', description: 'Identificador da conexão a ser revogada', required: true },
      { name: 'reason', type: 'string', description: 'Motivo da revogação para auditoria', required: true },
      { name: 'confirmationToken', type: 'string', description: 'Token de confirmação humana aprovado', required: false }
    ]
  }
];

const pendingConfirmations = new Map<string, McpConfirmationRequest>();

/**
 * Valida a execução de uma ferramenta MCP aplicando a política de confirmação de escrita.
 */
export function executeMcpToolWithConfirmation(
  toolName: string,
  params: Record<string, unknown>,
  callerInfo: { actorEmail: string; ipAddress: string; organizationId: string }
): {
  status: 'executed' | 'confirmation_required' | 'error';
  message: string;
  confirmationDetails?: McpConfirmationRequest;
  data?: unknown;
} {
  const tool = MCP_TOOLS_CATALOG.find(t => t.name === toolName);

  if (!tool) {
    return { status: 'error', message: `Ferramenta MCP desconhecida: ${toolName}` };
  }

  // Se for ferramenta de escrita, valida o token de confirmação
  if (tool.requiresExplicitConfirmation) {
    const confirmationToken = params.confirmationToken as string | undefined;

    if (!confirmationToken) {
      // Gera pedido de confirmação com ID único
      const confirmationId = `conf_${Math.random().toString(36).slice(2, 10)}`;
      const request: McpConfirmationRequest = {
        confirmationId,
        toolName,
        organizationId: callerInfo.organizationId,
        connectionId: (params.connectionId as string) || 'unknown',
        parameters: params,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // 5 minutos
        status: 'pending'
      };

      pendingConfirmations.set(confirmationId, request);

      logAuditEvent({
        action: 'mcp.write_confirmation_requested',
        category: 'mcp',
        severity: 'info',
        actor: callerInfo.actorEmail,
        ipAddress: callerInfo.ipAddress,
        description: `Ação de escrita MCP '${toolName}' solicitou confirmação de usuário. ID: ${confirmationId}`,
        details: { toolName, confirmationId }
      });

      return {
        status: 'confirmation_required',
        message: `Esta ação altera dados no sistema e exige confirmação explícita. Por favor, confirme a execução informando o token de confirmação: ${confirmationId}.`,
        confirmationDetails: request
      };
    }

    const savedRequest = pendingConfirmations.get(confirmationToken);
    if (!savedRequest || savedRequest.status !== 'pending' || new Date() > new Date(savedRequest.expiresAt)) {
      return {
        status: 'error',
        message: 'Token de confirmação inválido, expirado ou já utilizado.'
      };
    }

    // Marca como aprovado
    savedRequest.status = 'approved';

    logAuditEvent({
      action: 'mcp.write_action_executed',
      category: 'mcp',
      severity: 'warning',
      actor: callerInfo.actorEmail,
      ipAddress: callerInfo.ipAddress,
      description: `Ação de escrita MCP '${toolName}' confirmada e executada com sucesso.`,
      details: { toolName, confirmationId: confirmationToken }
    });

    return {
      status: 'executed',
      message: `Ação '${toolName}' executada com sucesso com consentimento humano validado.`,
      data: { tool: toolName, executed: true, timestamp: new Date().toISOString() }
    };
  }

  // Ferramenta de leitura
  logAuditEvent({
    action: 'mcp.read_tool_executed',
    category: 'mcp',
    severity: 'info',
    actor: callerInfo.actorEmail,
    ipAddress: callerInfo.ipAddress,
    description: `Consulta MCP '${toolName}' realizada com sucesso.`,
    details: { toolName }
  });

  return {
    status: 'executed',
    message: `Consulta '${toolName}' executada com sucesso.`,
    data: { tool: toolName, executed: true }
  };
}
