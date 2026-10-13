FROM node:24-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY app.js server.js ./
USER node
EXPOSE 3000
CMD ["node", "server.js"]
