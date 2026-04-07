FROM node:20-bookworm-slim

WORKDIR /dashboard

COPY package.json ./
RUN npm install --legacy-peer-deps

COPY . .

EXPOSE 5173

ENTRYPOINT []
CMD ["npm", "run", "dev"]
