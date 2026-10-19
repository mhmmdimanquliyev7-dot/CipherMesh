# PostgreSQL for the Railway trial demonstration (docs/deployment/railway-demo.md): the same pinned
# image as the cloud stack, TLS 1.3 only, reachable only over Railway's private network. The server
# certificate is signed by a private CA (the API verifies it with sslmode=verify-full); the key
# arrives as a secret variable and is written to /tmp at start, never into the image.
FROM postgres:17.11-alpine3.24@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24
COPY infrastructure/railway/postgres/pg_hba.conf /etc/ciphermesh/pg_hba.conf
COPY infrastructure/railway/postgres/start.sh /usr/local/bin/cm-pg-start
RUN chmod 0555 /usr/local/bin/cm-pg-start && chmod 0444 /etc/ciphermesh/pg_hba.conf
ENV PGDATA=/var/lib/postgresql/data/pgdata
ENTRYPOINT ["/usr/local/bin/cm-pg-start"]
