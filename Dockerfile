# Portable container image — works on Railway, Fly.io, Cloud Run, etc.
FROM node:22-slim

WORKDIR /app

# Install dependencies first for better layer caching.
COPY package*.json ./
RUN npm install --omit=dev

# App source
COPY . .

ENV NODE_ENV=production
ENV PORT=3000
# Persist the SQLite database here; mount a volume at /app/data to keep data.
ENV DATA_DIR=/app/data

EXPOSE 3000
CMD ["npm", "start"]
