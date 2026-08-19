# HTTP forward proxy: static Go binary on a distroless-style minimal base.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
# Build in the module context so go.sum + any pkg/ imports resolve.
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY httpproxy ./httpproxy
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/httpproxy ./httpproxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/httpproxy /httpproxy
USER nonroot:nonroot
ENTRYPOINT ["/httpproxy"]
