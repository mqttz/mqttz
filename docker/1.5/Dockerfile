FROM alpine:3.8

LABEL maintainer="Roger Light <roger@atchoo.org>" \
	 description="Eclipse Mosquitto MQTT Broker"

ENV VERSION=1.5.3 \
	 DOWNLOAD_SHA256=3081a998d303a883b1cd064009beabc88aa9159e26f5258a4ae6007160491d10 \
	 GPG_KEYS=A0D6EEA1DCAE49A635A3B2F0779B22DFB3E717B7

RUN set -x && \
	 apk --no-cache add --virtual build-deps \
      build-base \
	  gnupg \
      libressl-dev \
      libwebsockets-dev \
      util-linux-dev && \
    wget https://mosquitto.org/files/source/mosquitto-${VERSION}.tar.gz -O /tmp/mosq.tar.gz && \
	echo "$DOWNLOAD_SHA256  /tmp/mosq.tar.gz" | sha256sum -c - && \
    wget https://mosquitto.org/files/source/mosquitto-${VERSION}.tar.gz.asc -O /tmp/mosq.tar.gz.asc && \
	export GNUPGHOME="$(mktemp -d)" && \
	found=''; \
	for server in \
		ha.pool.sks-keyservers.net \
		hkp://keyserver.ubuntu.com:80 \
		hkp://p80.pool.sks-keyservers.net:80 \
		pgp.mit.edu \
	; do \
		echo "Fetching GPG key $GPG_KEYS from $server"; \
		gpg --keyserver "$server" --keyserver-options timeout=10 --recv-keys "$GPG_KEYS" && found=yes && break; \
	done; \
	test -z "$found" && echo >&2 "error: failed to fetch GPG key $GPG_KEYS" && exit 1; \
	gpg --batch --verify /tmp/mosq.tar.gz.asc /tmp/mosq.tar.gz && \
	gpgconf --kill all && \
	rm -rf "$GNUPGHOME" /tmp/mosq.tar.gz.asc && \
	mkdir -p /build && \
	tar --strip=1 -xf /tmp/mosq.tar.gz -C /build && \
	rm /tmp/mosq.tar.gz && \
    make -C /build -j "$(nproc)" \
      WITH_ADNS=no \
	  WITH_DOCS=no \
      WITH_MEMORY_TRACKING=no \
	  WITH_SHARED_LIBRARIES=no \
      WITH_SRV=no \
	  WITH_STRIP=yes \
      WITH_TLS_PSK=no \
      WITH_WEBSOCKETS=yes \
      prefix=/usr \
      binary && \
	addgroup -S mosquitto 2>/dev/null && \
    adduser -S -D -H -h /var/empty -s /sbin/nologin -G mosquitto -g mosquitto mosquitto 2>/dev/null && \
    mkdir -p /mosquitto/config /mosquitto/data /mosquitto/log && \
	install -d /usr/sbin/ && \
	install -s -m755 /build/src/mosquitto /usr/sbin/mosquitto && \
	install -m644 /build/mosquitto.conf /mosquitto/config/mosquitto.conf && \
    chown -R mosquitto:mosquitto /mosquitto && \
	apk --no-cache add \
      libuuid \
      libwebsockets && \
	apk del build-deps && \
	rm -rf /build /etc/apk /lib/apk

VOLUME ["/mosquitto/data", "/mosquitto/log"]

# Set up the entry point script and default command
COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
