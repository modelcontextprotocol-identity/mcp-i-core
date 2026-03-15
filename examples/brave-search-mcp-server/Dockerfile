FROM node:alpine@sha256:636c5bc8fa6a7a542bc99f25367777b0b3dd0db7d1ca3959d14137a1ac80bde2 AS builder

RUN apk add --no-cache openssl=3.5.5-r0

WORKDIR /app

COPY ./package.json ./package.json
COPY ./package-lock.json ./package-lock.json

RUN npm ci --ignore-scripts

COPY ./src ./src
COPY ./tsconfig.json ./tsconfig.json

RUN npm run build

FROM node:alpine@sha256:636c5bc8fa6a7a542bc99f25367777b0b3dd0db7d1ca3959d14137a1ac80bde2 AS release

RUN apk add --no-cache openssl=3.5.5-r0

WORKDIR /app

COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/package.json /app/package.json
COPY --from=builder /app/package-lock.json /app/package-lock.json

ENV NODE_ENV=production

RUN npm ci --ignore-scripts --omit-dev

USER node

ENTRYPOINT ["node", "dist/index.js"]
