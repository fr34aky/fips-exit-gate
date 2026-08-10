# fake-cashu-mint: a Cashu mint test double for the accept-and-melt flow.
# Not for production. Distroless.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/fake-cashu-mint ./cmd/fake-cashu-mint
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/fake-cashu-mint ./cmd/fake-cashu-mint

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fake-cashu-mint /fake-cashu-mint
USER nonroot:nonroot
ENTRYPOINT ["/fake-cashu-mint"]
