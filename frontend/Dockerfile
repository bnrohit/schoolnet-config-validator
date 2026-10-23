FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

# Use same-origin API calls in the production image so the browser talks to
# the frontend Nginx proxy instead of the user's own localhost:8000.
ARG VITE_API_URL=.
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

# Security baseline: current stable NGINX with October 2026 fixes.
# Do not downgrade below 1.30.6.
FROM nginx:1.30.6-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
