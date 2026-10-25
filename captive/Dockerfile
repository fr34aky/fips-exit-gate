# Captive daemon: static Go binary on a distroless-style minimal base.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
# Build in the module context so the pkg/ imports (pkg/metrics) resolve.
COPY go.mod ./
COPY pkg ./pkg
COPY captive ./captive
# Build version (git describe); see pkg/version and CONTRIBUTING.md#releasing.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X github.com/fr34aky/fips-exit-gate/pkg/version.Version=${VERSION}" \
    -o /out/captive ./captive

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/captive /captive
USER nonroot:nonroot
ENTRYPOINT ["/captive"]
