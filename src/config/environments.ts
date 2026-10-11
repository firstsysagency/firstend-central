/**
 * CONFIGURAÇÃO E ISOLAMENTO DE AMBIENTES (PRODUÇÃO VS HOMOLOGAÇÃO)
 * Central de Chaves Zatten — Checklist de Deploy 297
 */

import { z } from 'zod';

export type AppEnvironment = 'development' | 'staging' | 'production';

export const environmentConfigSchema = z.object({
  environment: z.enum(['development', 'staging', 'production']),
  isProduction: z.boolean(),
  panelUrl: z.string().url(),
  apiUrl: z.string().url(),
  oauthUrl: z.string().url(),
  mcpUrl: z.string().url(),
  openBaoUrl: z.string().url(),
  databaseName: z.string(),
  allowMockKeys: z.boolean(),
  requireStrictTls: z.boolean()
});

export type EnvironmentConfig = z.infer<typeof environmentConfigSchema>;

export const PRODUCTION_ENV_CONFIG: EnvironmentConfig = {
  environment: 'production',
  isProduction: true,
  panelUrl: 'https://keys.firstsys.com.br',
  apiUrl: 'https://keys.firstsys.com.br/api',
  oauthUrl: 'https://auth.firstsys.com.br',
  mcpUrl: 'https://mcp.firstsys.com.br/mcp',
  openBaoUrl: 'http://openbao:8200',
  databaseName: 'zatten_central_prod',
  allowMockKeys: false,
  requireStrictTls: true
};

export const STAGING_ENV_CONFIG: EnvironmentConfig = {
  environment: 'staging',
  isProduction: false,
  panelUrl: 'https://keys-staging.firstsys.com.br',
  apiUrl: 'https://keys-staging.firstsys.com.br/api',
  oauthUrl: 'https://auth-staging.firstsys.com.br',
  mcpUrl: 'https://mcp-staging.firstsys.com.br/mcp',
  openBaoUrl: 'http://openbao-staging:8200',
  databaseName: 'zatten_central_staging',
  allowMockKeys: true,
  requireStrictTls: true
};

export const DEVELOPMENT_ENV_CONFIG: EnvironmentConfig = {
  environment: 'development',
  isProduction: false,
  panelUrl: 'http://localhost:5173',
  apiUrl: 'http://localhost:3000/api',
  oauthUrl: 'http://localhost:8080/auth',
  mcpUrl: 'http://localhost:3001/mcp',
  openBaoUrl: 'http://localhost:8200',
  databaseName: 'zatten_central_dev',
  allowMockKeys: true,
  requireStrictTls: false
};

export function getCurrentEnvironmentConfig(): EnvironmentConfig {
  const env = (import.meta.env.VITE_APP_ENV || (import.meta.env.PROD ? 'production' : 'development')) as AppEnvironment;
  
  switch (env) {
    case 'production':
      return environmentConfigSchema.parse(PRODUCTION_ENV_CONFIG);
    case 'staging':
      return environmentConfigSchema.parse(STAGING_ENV_CONFIG);
    default:
      return environmentConfigSchema.parse(DEVELOPMENT_ENV_CONFIG);
  }
}
