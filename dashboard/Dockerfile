FROM node:20-bookworm-slim

WORKDIR /dashboard

COPY package.json package-lock.json ./
RUN npm install

COPY . .

EXPOSE 5173

ENV HOST=0.0.0.0
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]