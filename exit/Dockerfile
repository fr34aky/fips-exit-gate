# fips-exit clearnet service: Dante sockd built from source.
# Derived from the upstream socks5-dante-proxy two-stage build, but stripped of
# user management (auth is by source address in nftables, not SOCKS creds).

# ---- build stage -----------------------------------------------------------
FROM docker.io/bitnami/minideb:trixie AS build

ARG DANTE_VERSION=1.4.4
ARG DANTE_URL="https://www.inet.no/dante/files/dante-${DANTE_VERSION}.tar.gz"
ARG DANTE_SHA256="1973c7732f1f9f0a4c0ccf2c1ce462c7c25060b25643ea90f9b98f53a813faec"

RUN install_packages build-essential ca-certificates curl

WORKDIR /src
RUN curl -fsSL "$DANTE_URL" -o /tmp/dante.tar.gz \
    && echo "${DANTE_SHA256}  /tmp/dante.tar.gz" | sha256sum -c - \
    && tar xzf /tmp/dante.tar.gz --strip-components=1 -C /src

RUN ./configure CFLAGS="-O2" --sysconfdir=/etc --without-upnp --without-libwrap \
    && make -j"$(nproc)" \
    && make install DESTDIR=/out

# ---- runtime stage ---------------------------------------------------------
FROM docker.io/bitnami/minideb:trixie AS runtime

LABEL org.opencontainers.image.title="fips-exit clearnet (dante)"

# gettext-base provides envsubst for rendering the config at start.
RUN install_packages gettext-base

COPY --from=build /out/ /

# Minimal accounts for the unprivileged worker.
RUN echo 'root:x:0:0:root:/root:/bin/bash' > /etc/passwd \
    && echo 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin' >> /etc/passwd \
    && echo 'root:x:0:' > /etc/group \
    && echo 'nogroup:x:65534:' >> /etc/group

WORKDIR /srv
COPY sockd.conf entrypoint.sh /srv/
RUN chmod +x /srv/entrypoint.sh

# Rendered at runtime from these (see entrypoint.sh / deploy).
ENV FIPS_IF=fips0 \
    EXTERNAL_IF=eth0 \
    CLEARNET_PORT=1080

ENTRYPOINT ["/srv/entrypoint.sh"]
