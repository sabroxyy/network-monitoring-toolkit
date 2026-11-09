# syntax=docker/dockerfile:1.7
# ---------- build: produce a wheel ----------
FROM python:3.12-slim-bookworm AS build
WORKDIR /src
RUN pip install --no-cache-dir build==1.2.2
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

# ---------- runtime ----------
FROM python:3.12-slim-bookworm
ARG NETMON_UID=10001
LABEL org.opencontainers.image.title="netmon" \
      org.opencontainers.image.description="Safe, scheduled Nmap network monitoring" \
      org.opencontainers.image.licenses="MIT"

# nmap + libcap (for setcap). Raw-socket capability is granted to the nmap binary
# ONLY, so the Python process never needs root. It takes effect only if the
# container is started with --cap-add NET_RAW (and nmap.privileged: true).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap libcap2-bin tini \
 && setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)" \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl \
 && useradd --system --uid "${NETMON_UID}" --home-dir /var/lib/netmon --create-home netmon \
 && mkdir -p /etc/netmon && chown netmon:netmon /var/lib/netmon

USER netmon
WORKDIR /var/lib/netmon
ENV NETMON_CONFIG=/etc/netmon/config.yaml \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
VOLUME ["/var/lib/netmon"]
EXPOSE 9105
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:9105/metrics', timeout=4)" || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "netmon"]
CMD ["run"]
