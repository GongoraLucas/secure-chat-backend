# syntax=docker/dockerfile:1
# --- build: compila TypeScript con todas las dependencias ---
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json nest-cli.json ./
COPY src ./src
RUN npm run build

# --- deps: solo dependencias de producción ---
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# --- runtime: sin compilador, sin devDependencies, usuario no-root ---
FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./
# Las claves llegan por volumen de solo lectura (/run/keys); nunca se copian en la imagen.
USER node
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1:3000/health || exit 1
CMD ["node", "dist/main.js"]
