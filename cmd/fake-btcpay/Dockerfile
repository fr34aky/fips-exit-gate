# fake-btcpay: a BTCPay Server test double for the fake-payments flow (see
# docs/phase4-btcpay.md). Not for production. Stdlib + backend/payments only.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY backend/payments ./backend/payments
COPY cmd/fake-btcpay ./cmd/fake-btcpay
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/fake-btcpay ./cmd/fake-btcpay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fake-btcpay /fake-btcpay
USER nonroot:nonroot
ENTRYPOINT ["/fake-btcpay"]
