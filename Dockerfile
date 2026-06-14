FROM python:3.13-alpine AS base
WORKDIR /opt/hyperglass
ENV HYPERGLASS_APP_PATH=/etc/hyperglass
ENV HYPERGLASS_HOST=0.0.0.0
ENV HYPERGLASS_PORT=8001
ENV HYPERGLASS_DEBUG=false
ENV HYPERGLASS_DEV_MODE=false
ENV HYPERGLASS_REDIS_HOST=redis
ENV HYPEGLASS_DISABLE_UI=true
ENV HYPERGLASS_CONTAINER=true
COPY . .

FROM base as ui
WORKDIR /opt/hyperglass/hyperglass/ui
RUN apk add build-base pkgconfig cairo-dev nodejs npm \
  && npm install -g npm@10.9.3 pnpm@11.6.0 \
  && npm --prefix /usr/lib/node_modules/npm install glob@11.1.0 \
  && pnpm install -P

FROM ui as hyperglass
WORKDIR /opt/hyperglass
# Install the pinned dependency set from the lockfile (the single source of
# truth), then the package itself without re-resolving deps. --no-deps is
# required: the lock is a complete closure and pins pillow past favicons'
# declared cap (resolved via [tool.uv] override-dependencies), so letting pip
# re-resolve would fail on favicons' pillow<11 metadata.
RUN pip3 install --no-deps -r requirements.lock \
  && pip3 install -e . --no-deps

EXPOSE ${HYPERGLASS_PORT}
CMD ["python3", "-m", "hyperglass.console", "start"]
