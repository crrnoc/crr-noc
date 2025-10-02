# ========================
# 1. Base image
# ========================
FROM node:20

# ========================
# 2. Set working directory
# ========================
WORKDIR /app

# ========================
# 3. Copy package files and install dependencies
# ========================
COPY package*.json ./
RUN npm install --production

# ========================
# 4. Copy rest of the project
# ========================
COPY . .

# ========================
# 5. Ensure uploads + public exist
# ========================
RUN mkdir -p /app/uploads /app/public

# ========================
# 6. Expose port (matches your server.js -> PORT=3000)
# ========================
EXPOSE 3000

# ========================
# 7. Start app
# ========================
CMD ["node", "server.js"]
