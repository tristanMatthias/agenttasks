# Build the agenttasks control plane (multi-tenant hosting for tasksd).
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agenttasks ./cmd/agenttasks

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
# Tenant DBs live here; mount a persistent disk at /data in production.
RUN mkdir -p /data/tenants && chown -R app /data
USER app
ENV AGENTTASKS_DATA_DIR=/data/tenants
ENV AGENTTASKS_BEHIND_PROXY=true
COPY --from=build /out/agenttasks /usr/local/bin/agenttasks
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/agenttasks"]
