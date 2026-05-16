# ---------- Etapa de build ----------
FROM node:20-alpine AS builder

WORKDIR /app

# Instalamos dependencias en una capa separada para aprovechar la caché
COPY package.json ./
RUN npm install

# Copiamos el resto del código y compilamos la SPA
COPY . .

# La URL del backend se inyecta en build-time como variable de entorno Vite
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

# ---------- Etapa de runtime ----------
FROM nginx:1.27-alpine AS runtime

# Configuración mínima de Nginx para servir una SPA con history API
COPY --from=builder /app/dist /usr/share/nginx/html

RUN echo 'server { \
  listen 3000; \
  server_name _; \
  root /usr/share/nginx/html; \
  index index.html; \
  location / { try_files $uri /index.html; } \
}' > /etc/nginx/conf.d/default.conf \
  && sed -i "s/listen       80;/listen 3000;/" /etc/nginx/conf.d/default.conf || true

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
