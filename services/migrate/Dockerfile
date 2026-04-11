FROM alpine:3.19

ADD https://github.com/golang-migrate/migrate/releases/download/v4.16.2/migrate.linux-amd64.tar.gz /tmp/
RUN tar -xzf /tmp/migrate.linux-amd64.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/migrate && \
    rm /tmp/migrate.linux-amd64.tar.gz

COPY ./migrations /migrations

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["migrate -path /migrations -database $DATABASE_URL up"]
