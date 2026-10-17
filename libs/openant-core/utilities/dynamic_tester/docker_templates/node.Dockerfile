FROM node:24-slim
WORKDIR /test
COPY package.json .
# 构建阶段也需要 TypeScript 等 devDependencies；运行时不执行 npm/npx。
RUN npm install --include=dev --no-audit --no-fund
# 上下文只包含预置目标、生成的 harness 和依赖清单。
COPY . .
# ESM 改用 .mjs；TypeScript 先在构建阶段编译，再运行 dist 内产物。
CMD ["node", "test_exploit.cjs"]
