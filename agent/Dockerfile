# Exit-agent image. Unlike the captive daemon it needs the nft binary at
# runtime (it drives netfilter), so it runs on a slim Debian base rather than
# distroless. Deploy with host networking + CAP_NET_ADMIN.
FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY pkg ./pkg
COPY agent ./agent
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/agent ./agent

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/agent /usr/local/bin/fips-exit-agent
ENTRYPOINT ["/usr/local/bin/fips-exit-agent"]
