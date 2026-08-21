# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY config/ ./config/
COPY fp/ ./fp/
COPY h2fp/ ./h2fp/
COPY mgmt/ ./mgmt/
COPY mitm/ ./mitm/
COPY proxy/ ./proxy/
COPY rewrite/ ./rewrite/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/impersonate-proxy .

# distroless:nonroot runs as uid/gid 65532 — no shell, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/impersonate-proxy /impersonate-proxy

EXPOSE 8080 8081
ENTRYPOINT ["/impersonate-proxy"]
CMD ["-config", "/config.yaml"]
