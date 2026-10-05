# Lock-voting safety audit service — multi-stage image.

# ---- runtime image ----------------------------------------------------------
FROM node:20-alpine AS runtime

# Run as an unprivileged user; the base image ships a "node" account.
USER node
WORKDIR /app

# Zero third-party dependencies: copy sources and package metadata only.
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]

# ---- verification image: runtime + lock-rule tests --------------------------
FROM runtime AS verify
COPY --chown=node:node test ./test
# One-shot: lock-rule checks in-process, HTTP smoke against the audit service
# via AUDIT_BASE_URL, then exit with a status code carrying the result.
ENV AUDIT_BASE_URL=http://audit:8080
CMD ["node", "test/verify.js"]
