# fips-exit backend: static Go binary on distroless.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY backend ./backend
# Build version (git describe); see pkg/version and CONTRIBUTING.md#releasing.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X github.com/fr34aky/fips-exit-gate/pkg/version.Version=${VERSION}" -o /out/backend ./backend

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/backend /backend
USER nonroot:nonroot
ENTRYPOINT ["/backend"]
