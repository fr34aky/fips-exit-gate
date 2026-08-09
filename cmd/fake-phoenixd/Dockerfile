# fake-phoenixd: a phoenixd test double for the Lightning fake-payments flow.
# Not for production. Stdlib + backend/payments only; distroless.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY backend/payments ./backend/payments
COPY cmd/fake-phoenixd ./cmd/fake-phoenixd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/fake-phoenixd ./cmd/fake-phoenixd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fake-phoenixd /fake-phoenixd
USER nonroot:nonroot
ENTRYPOINT ["/fake-phoenixd"]
