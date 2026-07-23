# STEP 1: build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# STEP 2: production stage
FROM nginx:alpine

# Custom config (separate file, not default.conf override blindly — see nginx.conf below)
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

# Non-root user
RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup

# Give appuser write access to EVERYTHING nginx needs at runtime:
# html (static assets), cache, conf.d, the pid file location, and logs.
RUN chown -R appuser:appgroup /usr/share/nginx/html \
    && chown -R appuser:appgroup /var/cache/nginx \
    && chown -R appuser:appgroup /etc/nginx/conf.d \
    && chown -R appuser:appgroup /var/log/nginx \
    && touch /run/nginx.pid \
    && chown appuser:appgroup /run/nginx.pid

USER 1001
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
