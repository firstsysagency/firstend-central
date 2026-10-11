# ==============================================================================
# CENTRAL DE CHAVES ZATTEN — DOCKERFILE PRODUÇÃO (Express 5 + Vite SPA)
# Compatível com Coolify, Cloudflare Tunnel e Deploy Automatizado Firstsys
# ==============================================================================

FROM node:22-alpine

WORKDIR /app

# Instalar dependências necessárias do sistema
RUN apk add --no-cache libc6-compat wget

# Instalar dependências do projeto
COPY package*.json ./
RUN npm install

# Copiar código fonte completo
COPY . .

# Gerar build de produção do Vite (dist/)
RUN npm run build

# Configuração de runtime de produção
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000 80

# Health check interno para Coolify / Traefik
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

# Inicializar servidor Express 5 (Backend API + OAuth 2.1 + MCP + SPA Frontend)
CMD ["npx", "tsx", "server/index.ts"]
