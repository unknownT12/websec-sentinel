# WebSec Sentinel Docker runtime
# This avoids old macOS native binary issues by running Node/tsx inside Linux.
FROM node:20-bookworm-slim AS deps

WORKDIR /app

# Keep install deterministic and avoid unnecessary npm noise.
ENV NODE_ENV=development \
    npm_config_fund=false \
    npm_config_audit=false

COPY package*.json ./
RUN npm ci

FROM node:20-bookworm-slim AS runner

WORKDIR /app

ENV NODE_ENV=production \
    npm_config_fund=false \
    npm_config_audit=false

COPY --from=deps /app/node_modules ./node_modules
COPY package*.json ./
COPY tsconfig.json ./
COPY src ./src
COPY tools ./tools
COPY README.md LICENSE ./
COPY docs ./docs
COPY examples ./examples

# Build TypeScript inside Linux, not on macOS.
RUN npm run build

# Reports are written here when --save is used.
RUN mkdir -p /app/reports && chown -R node:node /app
USER node

ENTRYPOINT ["node", "dist/index.js"]
CMD ["--help"]
