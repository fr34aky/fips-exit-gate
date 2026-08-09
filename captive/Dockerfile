# Captive daemon: static Go binary on a distroless-style minimal base.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
# Build in the module context (the whole repo) so pkg/ is available later.
COPY go.mod ./
COPY captive ./captive
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/captive ./captive

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/captive /captive
USER nonroot:nonroot
ENTRYPOINT ["/captive"]
