# 最小 OCI 制品：只带 node 与 server.mjs，stdio 传输，无网络访问需求
FROM node:22-alpine
WORKDIR /app
COPY server.mjs README.md package.json ./
# MCP stdio：客户端通过 stdin/stdout 通信
ENTRYPOINT ["node", "/app/server.mjs"]
