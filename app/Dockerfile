# Build stage: compiles a static binary. The Go toolchain and module cache stay in this stage.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/tasky .

# Runtime stage: only the binary, static assets and wizexercise.txt
FROM alpine:3.24 AS release
RUN addgroup -S -g 10001 app && adduser -S -D -H -u 10001 -G app app

WORKDIR /app
COPY --from=build /out/tasky ./tasky
COPY assets ./assets
COPY wizexercise.txt /app/wizexercise.txt

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/app/tasky"]
