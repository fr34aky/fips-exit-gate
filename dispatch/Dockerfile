# Connectivity dispatcher: static Go binary on a distroless-style minimal base.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
# Build in the module context so any pkg/ imports resolve.
COPY go.mod ./
COPY pkg ./pkg
COPY dispatch ./dispatch
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/dispatch ./dispatch

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dispatch /dispatch
USER nonroot:nonroot
ENTRYPOINT ["/dispatch"]
