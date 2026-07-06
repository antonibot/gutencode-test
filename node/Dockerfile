FROM node:22-alpine
WORKDIR /app
COPY . .
# zero production dependencies -- nothing to install (see package.json)
# Postgres / Supabase?  RUN npm install --no-save pg   (see .env.example)
RUN mkdir -p /data && chown node:node /data
USER node
ENV HOST=0.0.0.0 PORT=8080 DATABASE_PATH=/data/app.db
EXPOSE 8080
VOLUME /data
CMD ["node", "server.js"]
