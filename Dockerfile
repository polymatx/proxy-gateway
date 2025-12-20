FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download || go mod tidy
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o proxy-gateway cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
RUN addgroup -g 1001 proxyuser && adduser -u 1001 -S proxyuser -G proxyuser
WORKDIR /app
COPY --from=builder /app/proxy-gateway .
RUN chown proxyuser:proxyuser proxy-gateway
USER proxyuser
EXPOSE 8080

CMD ["./proxy-gateway"]
