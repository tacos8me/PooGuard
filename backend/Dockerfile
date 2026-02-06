FROM node:20-alpine

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup \
    && mkdir -p /app/logs && chown -R appuser:appgroup /app/logs
USER appuser

EXPOSE 3001

CMD ["node", "src/index.js"]
