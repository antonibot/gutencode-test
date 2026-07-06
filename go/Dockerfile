FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/server ./cmd/server
# Postgres backend? that needs:  go get github.com/jackc/pgx/v5  &&  go build -tags postgres ./cmd/server
# (it edits go.mod/go.sum -> the verifier reports drift; acknowledge both files in .gutencode/accepted.json,
#  or pick the python/node image for the Postgres path. See DEPLOY.md.)

FROM alpine:3.20
RUN adduser -D app && mkdir -p /data && chown app:app /data
COPY --from=build /out/server /usr/local/bin/server
USER app
ENV HOST=0.0.0.0 PORT=8080 DATABASE_PATH=/data/app.db
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["server"]
