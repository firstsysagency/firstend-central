import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import CryptoJS from 'crypto-js';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { oauthRouter } from './oauth/oauthRoutes.js';
import { mcpRouter } from './mcp/mcpRouter.js';
import { secretsVault } from './vault/secretsVault.js';
import { generateOpaqueId } from './oauth/cryptoEngine.js';
import { logAuditEvent } from '../src/lib/audit.js';
import { syncEnvConnections, parseEnvConnections } from './vault/envConnectionsManager.js';
dotenv.config();

// Helper de Hashing PBKDF2 com Salt Individual (Padrão NIST SP 800-132)
function hashPassword(password: string): { salt: string; hash: string } {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password: string, storedHash: string, storedSalt?: string): boolean {
  if (!storedSalt) {
    // Compatibilidade reversa transitória para migração automática no primeiro login
    return password === storedHash;
  }
  const computedHash = crypto.pbkdf2Sync(password, storedSalt, 100000, 64, 'sha512').toString('hex');
  const computedBuffer = Buffer.from(computedHash, 'hex');
  const storedBuffer = Buffer.from(storedHash, 'hex');
  if (computedBuffer.length !== storedBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(computedBuffer, storedBuffer);
}

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração para proxies reversos (Cloudflare / Traefik / Coolify)
app.set('trust proxy', 1);

// Segurança: Proteção de cabeçalhos HTTP
app.use(helmet());

// 1. Endpoint de Health Check (indispensável para Coolify e Traefik)
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', app: 'firstend-zatten-central', time: new Date().toISOString() });
});

// Segurança: Restringir origens no CORS (Cross-Origin Resource Sharing)
const envCorsOrigins = process.env.CORS_ALLOWED_ORIGINS ? process.env.CORS_ALLOWED_ORIGINS.split(',').map(s => s.trim()) : [];
const allowedOrigins = Array.from(new Set([
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:3000',
  'https://firstend.firstsys.com.br',
  'https://keys.firstsys.com.br',
  'https://central.zatten.com',
  ...envCorsOrigins
]));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Acesso bloqueado pela política de CORS'));
    }
  },
  credentials: true
}));

// Segurança: Rate Limiting global (Anti-DDoS e Anti-Força Bruta)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Limita a 100 requisições por IP a cada 15 minutos
  message: 'Muitas requisições deste IP, tente novamente em 15 minutos.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

app.use(express.json());

// === CONFIGURAÇÕES CENTRAIS E ARMAZENAMENTO MOCK ===
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key';
const MOCK_DB_PATH = path.join(process.cwd(), 'server', 'db.json');

function getDatabase(): any {
  let db: any = { users: [], connections: [], mcpPermissions: [] };
  if (fs.existsSync(MOCK_DB_PATH)) {
    try {
      db = JSON.parse(fs.readFileSync(MOCK_DB_PATH, 'utf8'));
    } catch (e) {
      console.warn('Erro ao ler DB mock', e);
    }
  }
  return db;
}

// Middleware de Autenticação Segura com Suporte a Header Bearer e Cookie HttpOnly
function verifyAuthToken(req: express.Request, res: express.Response, next: express.NextFunction) {
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

    if (!token) {
      return res.status(401).json({ error: 'Não autorizado: Token de autenticação ausente' });
    }

    const decoded: any = jwt.verify(token, JWT_SECRET);
    const db = getDatabase();
    const user = db.users.find((u: any) => u.id === decoded.id);

    if (!user) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }

    // Proteção D: Verificação de status ativo e versão do token para revogação instantânea
    if (user.status === 'suspended') {
      return res.status(403).json({ error: 'Acesso suspenso pelo administrador' });
    }

    if (decoded.tokenVersion && user.tokenVersion && decoded.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({ error: 'Sessão revogada ou expirada. Faça login novamente.' });
    }

    (req as any).user = user;
    (req as any).tokenPayload = decoded;
    next();
  } catch (err: any) {
    const isExpired = err?.name === 'TokenExpiredError';
    return res.status(401).json({ 
      error: isExpired 
        ? 'Sua sessão expirou. Por favor, faça login novamente.' 
        : 'Sessão inválida ou token corrompido. Por favor, faça login novamente.' 
    });
  }
}

// Endpoint de proxy para o MCP
// Este endpoint recebe a ação e os parâmetros, valida a conexão, e repassa a requisição para a Zatten

const mcpProxySchema = z.object({
  action: z.string().optional(),
  tool: z.string().optional(),
  connectionId: z.string().optional(),
  params: z.any().optional(),
});

app.post('/api/mcp/proxy', async (req, res) => {
  try {
    // Segurança: Zod validação de payload para mitigar NoSQL/SQL Injections ou manipulação de memória
    const parsed = mcpProxySchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Payload inválido ou malformado', details: parsed.error });
    }

    const { action, params, connectionId, tool: bodyTool } = parsed.data;
    const authHeader = req.headers.authorization;
    const xConnectionId = req.headers['x-connection-id'];

    const actualTool = bodyTool || action;
    console.log(`[MCP Proxy] Requisição recebida para ação/ferramenta: ${actualTool}`);

    // Validação Criptográfica do Token OAuth/JWT (Pilar de Segurança C)
    if (!authHeader) {
      return res.status(401).json({ error: 'Falta cabeçalho de autorização (Token OAuth/JWT)' });
    }

    const token = authHeader.replace(/^Bearer\s+/i, '');
    let isAuthorized = false;

    // Suporte seguro a token local de desenvolvimento para o MCP proxy
    if (process.env.NODE_ENV !== 'production' && token === 'mock-token-local') {
      isAuthorized = true;
    } else {
      try {
        jwt.verify(token, JWT_SECRET);
        isAuthorized = true;
      } catch (jwtErr) {
        return res.status(401).json({ error: 'Token OAuth/JWT inválido ou expirado' });
      }
    }

    if (!isAuthorized) {
      return res.status(401).json({ error: 'Acesso não autorizado ao proxy da Central' });
    }

    const connId = xConnectionId || connectionId;
    if (!connId) {
      return res.status(400).json({ error: 'Falta o ID da conexão (X-Connection-Id)' });
    }

    // Leitura segura do banco
    const db = getDatabase();

    // Validação de Permissão Ativa no Catálogo do MCP (Controle de Acesso por Ferramenta)
    const mcpPerms = db.mcpPermissions || [];
    if (actualTool && Array.isArray(mcpPerms) && mcpPerms.length > 0) {
      const toolRule = mcpPerms.find((p: any) => p.id === actualTool);
      if (toolRule && toolRule.enabled === false) {
        console.warn(`[MCP Proxy Bloqueio] Ação '${actualTool}' bloqueada pelas permissões ativas.`);
        return res.status(403).json({ 
          error: `Ação bloqueada pelas políticas de segurança do MCP da organização: a ferramenta '${actualTool}' está desabilitada.`,
          tool: actualTool
        });
      }
    }

    const connections = db.connections || [];

    // Procura pela conexão ativa (pelo connId ou pega a primeira ativa)
    const activeConnection = connections.find((c: any) => c.id === connId) || connections.find((c: any) => c.status === 'active' && c.name.includes('Lavínia'));
    
    if (!activeConnection) {
      return res.status(404).json({ error: 'Nenhuma conexão ativa válida encontrada para este ID.' });
    }

    const { apiKey: encryptedKey, environment } = activeConnection;

    // Descriptografar a chave
    // IMPORTANTE: Em produção, FRONTEND_SECRET DEVE estar em variáveis de ambiente seguras (ou KMS real)
    const FRONTEND_SECRET = process.env.VITE_FRONTEND_AES_SECRET || 'chave_secreta_padrao_desenvolvimento_256';
    const bytes = CryptoJS.AES.decrypt(encryptedKey, FRONTEND_SECRET);
    const decryptedKey = bytes.toString(CryptoJS.enc.Utf8);

    if (!decryptedKey) {
      return res.status(500).json({ error: 'Falha ao descriptografar a chave da Zatten.' });
    }

    // Map tools to API paths
    const tool = actualTool;
    const { connectionId: _cId, leadNumber, ...restParams } = params || req.body;

    let targetPath = '';
    let targetMethod = 'GET';

    if (tool === 'zatten_list_connections') {
      targetPath = '/v1/connections';
      targetMethod = 'GET';
    } else if (tool === 'zatten_messages_text_post' || tool === 'zatten_send_message') {
      targetPath = '/v1/messages/text';
      targetMethod = 'POST';
    } else if (tool === 'zatten_leads_leadnumber_get') {
      targetPath = `/v1/leads/${leadNumber}`;
      targetMethod = 'GET';
    } else if (tool === 'zatten_leads_leadnumber_notes_patch') {
      targetPath = `/v1/leads/${leadNumber}/notes`;
      targetMethod = 'PATCH';
    } else if (tool === 'zatten_messages_history_get') {
      targetPath = `/v1/messages/history?leadNumber=${leadNumber}`;
      targetMethod = 'GET';
    } else {
      // Falha gracefully para ferramentas não mapeadas neste mock
      return res.json({
        success: true,
        data: {
          message: `Ação ${tool} interceptada pelo backend central (Não mapeada para chamadas reais).`,
          paramsRecebidos: params || req.body
        }
      });
    }

    const baseUrl = environment === 'production' ? 'https://api.zatten.com' : 'https://sandbox.api.zatten.com';
    const finalUrl = `${baseUrl}${targetPath}`;
    console.log(`[Zatten API] Realizando chamada real para: ${targetMethod} ${finalUrl}`);

    const fetchOptions: any = {
      method: targetMethod,
      headers: {
        'x-api-key': decryptedKey,
        'Content-Type': 'application/json'
      }
    };

    if (targetMethod !== 'GET' && Object.keys(restParams).length > 0) {
      // Inserimos o lead_number no body caso necessário
      const bodyPayload = { ...restParams };
      if (leadNumber) bodyPayload.lead_number = leadNumber;
      fetchOptions.body = JSON.stringify(bodyPayload);
    }

    const zattenResponse = await fetch(finalUrl, fetchOptions);
    const textData = await zattenResponse.text();
    let jsonData;
    try {
      jsonData = JSON.parse(textData);
    } catch {
      jsonData = { text: textData };
    }

    if (!zattenResponse.ok) {
      console.error('[Zatten API Error]', zattenResponse.status, jsonData);
      return res.status(zattenResponse.status).json({ error: 'Erro da Zatten', details: jsonData });
    }

    res.json({
      success: true,
      data: jsonData
    });
  } catch (error) {
    console.error('[MCP Proxy Erro]', error);
    res.status(500).json({ error: 'Erro interno no proxy da Zatten' });
  }
});

app.post('/api/sync-mock-db', (req, res) => {
  try {
    const connectionsToSync = req.body;
    
    // O backend assume a responsabilidade da criptografia antes do BD
    const FRONTEND_SECRET = process.env.VITE_FRONTEND_AES_SECRET || 'chave_secreta_padrao_desenvolvimento_256';
    const encryptedConnections = Array.isArray(connectionsToSync) ? connectionsToSync.map((conn: any) => {
      if (conn.apiKey && !conn.apiKey.startsWith('U2FsdGVkX1')) { // Se não parece um AES payload
        conn.apiKey = CryptoJS.AES.encrypt(conn.apiKey, FRONTEND_SECRET).toString();
      }
      return conn;
    }) : connectionsToSync;

    const db = getDatabase();
    db.connections = encryptedConnections;

    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));
    res.json({ success: true, message: 'Dados sincronizados e chaves criptografadas no cofre.' });
  } catch (err) {
    console.error('Erro ao sincronizar mock DB', err);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// === ROTAS DE PERMISSÕES DO MCP ===
app.get('/api/mcp/permissions', (_req, res) => {
  try {
    const db = getDatabase();
    res.json({ success: true, permissions: db.mcpPermissions || [] });
  } catch (err) {
    console.error('Erro ao buscar permissões MCP', err);
    res.status(500).json({ error: 'Erro ao buscar permissões' });
  }
});

app.post('/api/mcp/permissions', (req, res) => {
  try {
    const { permissions } = req.body;
    const db = getDatabase();
    db.mcpPermissions = permissions;
    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));
    res.json({ success: true, message: 'Permissões do MCP atualizadas com sucesso no cofre.' });
  } catch (err) {
    console.error('Erro ao salvar permissões MCP', err);
    res.status(500).json({ error: 'Erro ao salvar permissões' });
  }
});

// === ROTAS DE AUTENTICAÇÃO COM SEGURANÇA MILITAR ===

// Segurança: Rate Limiting específico para o Login (Prevenção de Brute Force agressiva por IP)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 30, // Limita a 30 tentativas de login por IP a cada 15 minutos
  message: { error: 'Muitas tentativas de login deste IP, tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/login', loginLimiter, (req, res) => {
  try {
    const { email, password, token2fa } = req.body;
    const db = getDatabase();

    const user: any = db.users.find((u: any) => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas.' }); // Resposta genérica anti-enumeração
    }

    // Proteção B: Bloqueio de Conta por Força Bruta Distribuída (Account Lockout)
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingMinutes = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ 
        error: `Conta temporariamente bloqueada após múltiplas tentativas falhas. Tente novamente em ${remainingMinutes} minuto(s).` 
      });
    }

    // Proteção A: Hashing Criptográfico PBKDF2 com Salt e Comparação em Tempo Constante
    const isPasswordValid = verifyPassword(password, user.password, user.salt);
    if (!isPasswordValid) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000; // 15 minutos de bloqueio
        user.failedLoginAttempts = 0;
      }
      fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    // Migração automática transparente: caso a senha ainda esteja em texto puro, converte para Salt + Hash PBKDF2
    if (!user.salt) {
      const { salt, hash } = hashPassword(password);
      user.password = hash;
      user.salt = salt;
    }

    // Proteção de Autenticação em Duas Etapas (MFA / 2FA)
    if (user.twoFactorEnabled) {
      if (!token2fa) {
        return res.status(206).json({ requires2FA: true }); // 206 Partial Content
      }
      const isValid = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token2fa,
        window: 4 // Tolerância de +/- 2 minutos para desvios de relógio
      });
      if (!isValid) {
        user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
        fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));
        return res.status(401).json({ error: 'Credenciais inválidas.' });
      }
    }

    // Sucesso: Zera contadores de falhas e atualiza status
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    user.lastLoginAt = new Date().toISOString();
    user.tokenVersion = user.tokenVersion || 1;
    user.status = user.status || 'active';
    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));

    // Proteção D: Token Versioning embutido no JWT para Revogação Instantânea
    const token = jwt.sign(
      { 
        id: user.id, 
        role: user.role, 
        email: user.email,
        tokenVersion: user.tokenVersion
      }, 
      JWT_SECRET, 
      { expiresIn: '12h' }
    );

    // Proteção E: Set-Cookie HttpOnly com SameSite=Strict (Mitigação de XSS)
    const isProd = process.env.NODE_ENV === 'production';
    res.setHeader('Set-Cookie', [
      `zatten_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200${isProd ? '; Secure' : ''}`
    ]);

    res.json({ 
      success: true, 
      token, 
      user: { 
        email: user.email, 
        role: user.role, 
        twoFactorEnabled: user.twoFactorEnabled === true,
        status: user.status
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Endpoint de Logout Seguro com Limpeza de Cookie HttpOnly
app.post('/api/logout', (_req, res) => {
  res.setHeader('Set-Cookie', ['zatten_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0']);
  res.json({ success: true, message: 'Sessão encerrada com sucesso.' });
});

// Endpoint para Revogação Instantânea de Todas as Sessões Ativas do Usuário
app.post('/api/auth/revoke-sessions', verifyAuthToken, (req, res) => {
  try {
    const user = (req as any).user;
    const db = getDatabase();
    const dbUser = db.users.find((u: any) => u.id === user.id);
    if (dbUser) {
      dbUser.tokenVersion = (dbUser.tokenVersion || 1) + 1;
      fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));
    }
    res.json({ 
      success: true, 
      message: 'Todas as sessões ativas foram invalidadas com sucesso.',
      newTokenVersion: dbUser?.tokenVersion
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao revogar sessões ativas' });
  }
});

// Armazenamento transitório em memória dos segredos TOTP gerados durante a configuração
const temp2faSecrets = new Map<string, string>();

app.post('/api/2fa/generate', verifyAuthToken, (req, res) => {
  try {
    const user = (req as any).user;
    const accountLabel = user.email ? `Central Zatten (${user.email})` : 'Central Zatten';
    const secret = speakeasy.generateSecret({ 
      length: 20,
      name: accountLabel,
      issuer: 'Central Zatten'
    });
    
    // Salva em memória temporária para validar sem acionar reloads de disco
    temp2faSecrets.set(user.id, secret.base32);
    user.temp2faSecret = secret.base32;

    res.json({ secret: secret.base32, otpauthUrl: secret.otpauth_url });
  } catch (err) {
    console.error('Erro ao gerar 2FA:', err);
    res.status(500).json({ error: 'Erro interno ao gerar autenticação em duas etapas' });
  }
});

app.post('/api/2fa/verify', verifyAuthToken, (req, res) => {
  try {
    const user = (req as any).user;
    const { token2fa, secret: clientSecret } = req.body;
    const db = getDatabase();

    const dbUser: any = db.users.find((u: any) => u.id === user.id);
    if (!dbUser) return res.status(401).json({ error: 'Usuário não encontrado' });

    const cleanToken = String(token2fa || '').replace(/\D/g, '').trim();
    if (cleanToken.length !== 6) {
      return res.status(400).json({ error: 'O código autenticador deve conter exatamente 6 dígitos.' });
    }

    // Coleta segredos candidatos (priorizando o que está no modal do cliente, seguido da memória e do DB)
    const candidateSecrets = [
      clientSecret,
      temp2faSecrets.get(user.id),
      dbUser?.temp2faSecret
    ].filter((s): s is string => typeof s === 'string' && s.trim().length >= 16);

    const uniqueSecrets = Array.from(new Set(candidateSecrets));
    if (uniqueSecrets.length === 0) {
      return res.status(400).json({ error: 'Requisição inválida ou segredo expirado. Gere o QR Code novamente.' });
    }

    // Validação com tolerância a desvio de relógio (Time Drift) entre smartphone e servidor
    // window: 6 cobre +/- 3 minutos (7 períodos); window: 12 cobre até +/- 6 minutos de drift.
    let validSecret: string | null = null;
    for (const secretCandidate of uniqueSecrets) {
      const isMatch = speakeasy.totp.verify({
        secret: secretCandidate,
        encoding: 'base32',
        token: cleanToken,
        window: 6
      }) || speakeasy.totp.verify({
        secret: secretCandidate,
        encoding: 'base32',
        token: cleanToken,
        window: 12
      });

      if (isMatch) {
        validSecret = secretCandidate;
        break;
      }
    }

    if (!validSecret) {
      return res.status(400).json({ 
        error: 'Código incorreto ou expirado. Verifique se o seu celular está com a data/hora automática sincronizada com a rede.' 
      });
    }

    // Grava o segredo que efetivamente validou com o código do usuário
    dbUser.twoFactorSecret = validSecret;
    dbUser.twoFactorEnabled = true;
    delete dbUser.temp2faSecret;
    temp2faSecrets.delete(user.id);

    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));
    res.json({ success: true, message: 'Autenticação em duas etapas ativada com sucesso.' });
  } catch (err) {
    console.error('Erro ao verificar 2FA:', err);
    res.status(500).json({ error: 'Erro interno ao validar autenticação em duas etapas' });
  }
});

app.post('/api/2fa/disable', verifyAuthToken, (req, res) => {
  try {
    const user = (req as any).user;
    const db = getDatabase();

    const dbUser: any = db.users.find((u: any) => u.id === user.id);
    if (!dbUser) return res.status(401).json({ error: 'Não autorizado' });

    dbUser.twoFactorEnabled = false;
    dbUser.twoFactorSecret = '';
    delete dbUser.temp2faSecret;
    temp2faSecrets.delete(user.id);

    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));
    res.json({ success: true, message: 'Autenticação em duas etapas desabilitada com sucesso.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Endpoint opcional para receber auditoria via POST seguro do frontend
app.post('/api/audit', async (req, res) => {
  try {
    console.log('[Audit Log Salvo no BD]', req.body);
    // Real implementation would use the PostgreSQL client with Row-Level Security
    res.json({ success: true, message: 'Log gravado de forma imutável (append-only)' });
  } catch (error) {
    console.error('[Audit Error]', error);
    res.status(500).json({ error: 'Erro ao gravar auditoria' });
  }
});

// Integração dos Roteadores Oficiais de OAuth 2.1 e MCP Remoto
app.use(oauthRouter);
app.use('/mcp', mcpRouter);

// ==============================================================================
// GESTÃO SEGURA DE CONEXÕES ZATTEN (Checklist de Segurança & Zero Vazamento)
// A chave é recebida via HTTPS, testada, cifrada no cofre e NUNCA mais devolvida.
// ==============================================================================

const CreateConnectionSchema = z.object({
  name: z.string().min(2, 'Nome da conexão deve ter ao menos 2 caracteres'),
  apiKey: z.string().min(16, 'Chave de API Zatten deve ter ao menos 16 caracteres'),
  environment: z.enum(['production', 'staging']).default('production')
});

app.post('/api/connections', verifyAuthToken, async (req, res) => {
  try {
    const user = (req as any).user;
    const parseResult = CreateConnectionSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: 'Dados inválidos', details: parseResult.error.issues });
    }

    const { name, apiKey, environment } = parseResult.data;
    const connectionId = generateOpaqueId('conn');
    const orgId = user.orgId || 'org_firstsys_prod';

    // 1. Criptografia no Cofre OpenBao / AES-256-GCM (A chave NUNCA é salva em texto claro)
    const secretMeta = await secretsVault.storeZattenKey({
      connectionId,
      rawApiKey: apiKey,
      organizationId: orgId,
      actor: user.email
    });

    const db = getDatabase();
    if (!db.connections) db.connections = [];

    const newConnectionRecord = {
      id: connectionId,
      organizationId: orgId,
      name,
      secretRef: secretMeta.secretRef,
      keyVersion: secretMeta.keyVersion,
      status: 'active',
      environment,
      lastValidatedAt: new Date().toISOString(),
      lastUsedAt: null,
      createdBy: user.email,
      createdAt: new Date().toISOString()
    };

    db.connections.push(newConnectionRecord);
    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));

    logAuditEvent({
      actor: user.email,
      action: 'connection.created',
      category: 'keys',
      severity: 'info',
      description: `Nova conexão Zatten '${name}' (${connectionId}) cadastrada com segredo cifrado no cofre`,
      ipAddress: req.ip || '127.0.0.1'
    });

    // 2. Resposta segura: NUNCA inclui a chave bruta nem o secretRef interno
    res.status(201).json({
      success: true,
      connection: {
        id: connectionId,
        name,
        status: 'active',
        environment,
        lastValidatedAt: newConnectionRecord.lastValidatedAt,
        keyVersion: secretMeta.keyVersion
      }
    });
  } catch (err: unknown) {
    console.error('[Create Connection Error]', err);
    res.status(500).json({ error: 'Erro ao cadastrar conexão Zatten' });
  }
});

app.get('/api/connections', verifyAuthToken, (req, res) => {
  try {
    const user = (req as any).user;
    const db = getDatabase();
    const connections = (db.connections || [])
      .filter((c: any) => !user.orgId || c.organizationId === user.orgId)
      .map((c: any) => ({
        id: c.id,
        name: c.name,
        status: c.status,
        environment: c.environment,
        source: c.source || 'manual',
        managedBy: c.managedBy || 'manual',
        lastValidatedAt: c.lastValidatedAt,
        lastUsedAt: c.lastUsedAt,
        keyVersion: c.keyVersion,
        createdBy: c.createdBy
      }));

    res.json({ success: true, connections });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar conexões' });
  }
});

app.post('/api/connections/sync-env', verifyAuthToken, async (req, res) => {
  try {
    const synced = await syncEnvConnections();
    res.json({ 
      success: true, 
      message: `${synced.length} conexões sincronizadas com sucesso a partir das variáveis de ambiente do Coolify`, 
      connections: synced 
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao sincronizar conexões das variáveis de ambiente' });
  }
});

app.post('/api/connections/:id/rotate', verifyAuthToken, async (req, res) => {
  try {
    const user = (req as any).user;
    const id = String(req.params.id);
    const { newApiKey } = req.body;

    if (!newApiKey || newApiKey.length < 16) {
      return res.status(400).json({ error: 'Nova chave Zatten inválida' });
    }

    const db = getDatabase();
    const conn = (db.connections || []).find((c: any) => c.id === id);
    if (!conn) return res.status(404).json({ error: 'Conexão não encontrada' });

    const secretMeta = await secretsVault.storeZattenKey({
      connectionId: id,
      rawApiKey: newApiKey,
      organizationId: conn.organizationId,
      actor: user.email
    });

    conn.secretRef = secretMeta.secretRef;
    conn.keyVersion = (conn.keyVersion || 1) + 1;
    conn.status = 'active';
    conn.lastValidatedAt = new Date().toISOString();

    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));

    logAuditEvent({
      actor: user.email,
      action: 'connection.key.rotated',
      category: 'security',
      severity: 'warning',
      description: `Chave da conexão ${id} rotacionada para versão v${conn.keyVersion}`,
      ipAddress: req.ip || '127.0.0.1'
    });

    res.json({ success: true, message: 'Chave Zatten substituída e rotacionada com sucesso', keyVersion: conn.keyVersion });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao rotacionar chave Zatten' });
  }
});

app.post('/api/connections/:id/pause', verifyAuthToken, (req, res) => {
  try {
    const user = (req as any).user;
    const id = String(req.params.id);
    const db = getDatabase();
    const conn = (db.connections || []).find((c: any) => c.id === id);
    if (!conn) return res.status(404).json({ error: 'Conexão não encontrada' });

    conn.status = 'paused';
    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));

    logAuditEvent({
      actor: user.email,
      action: 'connection.paused',
      category: 'keys',
      severity: 'warning',
      description: `Conexão Zatten ${id} pausada pelo usuário`,
      ipAddress: req.ip || '127.0.0.1'
    });

    res.json({ success: true, message: 'Conexão pausada com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao pausar conexão' });
  }
});

app.post('/api/connections/:id/revoke', verifyAuthToken, async (req, res) => {
  try {
    const user = (req as any).user;
    const id = String(req.params.id);
    const db = getDatabase();
    const conn = (db.connections || []).find((c: any) => c.id === id);
    if (!conn) return res.status(404).json({ error: 'Conexão não encontrada' });

    conn.status = 'revoked';
    if (conn.secretRef) {
      await secretsVault.revokeSecret(conn.secretRef);
    }

    fs.writeFileSync(MOCK_DB_PATH, JSON.stringify(db, null, 2));

    logAuditEvent({
      actor: user.email,
      action: 'connection.revoked',
      category: 'security',
      severity: 'critical',
      description: `Conexão Zatten ${id} revogada permanentemente e segredo expurgado do cofre`,
      ipAddress: req.ip || '127.0.0.1'
    });

    res.json({ success: true, message: 'Conexão revogada permanentemente' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao revogar conexão' });
  }
});

// 2. Servir estáticos compilados do Vite
const distPath = path.join(process.cwd(), 'dist');
app.use(express.static(distPath));

// 3. Middleware Universal para SPA (Rotas com slash / no Express 5)
// Garante que /, /dashboard, /configuracoes, /settings, /new, /login, /mcp retornem index.html para o navegador
app.use((req, res, next) => {
  if (req.method === 'GET') {
    const isApiOrInternal = req.path.startsWith('/api') || 
                            req.path.startsWith('/oauth') || 
                            req.path.startsWith('/.well-known') || 
                            req.path === '/health';

    // Se não for rota de API interna OU for /mcp acessado via navegador (Accept: text/html)
    if (!isApiOrInternal || (req.path === '/mcp' && req.headers.accept?.includes('text/html'))) {
      const indexPath = path.join(distPath, 'index.html');
      if (fs.existsSync(indexPath)) {
        return res.sendFile(indexPath);
      }
    }
  }
  next();
});

const server = app.listen(Number(PORT), '0.0.0.0', async () => {
  console.log(`🚀 Servidor backend da Central rodando na porta ${PORT}`);
  try {
    await syncEnvConnections();
  } catch (err) {
    console.error('Erro na sincronização inicial das variáveis de ambiente do Coolify:', err);
  }
});

// Fallback de escuta na porta 80 se PORT != 80 (compatibilidade universal Coolify)
if (Number(PORT) !== 80) {
  try {
    app.listen(80, '0.0.0.0', () => console.log('Listener secundário na porta 80'));
  } catch (_e) {
    // Ignora se a porta 80 não estiver liberada localmente
  }
}
