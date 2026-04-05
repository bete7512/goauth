# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy entire source (needed for internal/ packages)
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./demo/backend

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /server /server

EXPOSE 8080

CMD ["/server"]
