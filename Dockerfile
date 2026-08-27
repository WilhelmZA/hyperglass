FROM python:3.13-alpine AS base
WORKDIR /opt/hyperglass
ENV HYPERGLASS_APP_PATH=/etc/hyperglass
ENV HYPERGLASS_HOST=0.0.0.0
ENV HYPERGLASS_PORT=8001
ENV HYPERGLASS_DEBUG=false
ENV HYPERGLASS_DEV_MODE=false
ENV HYPERGLASS_REDIS_HOST=redis
ENV HYPERGLASS_DISABLE_UI=false
ENV HYPERGLASS_CONTAINER=true
COPY . .

FROM base AS ui
WORKDIR /opt/hyperglass/hyperglass/ui
# The glob patch that used to sit here is gone. It ran `npm --prefix
# /usr/lib/node_modules/npm install glob@11.1.0`, which fails the build: installing
# into npm's own tree makes npm reconcile npm's package.json, whose devDependencies
# include the unpublished `@npmcli/docs`, so the install 404s. It is also no longer
# needed, since the npm shipped by alpine bundles glob 13.x already.
# npm's bundled tar release is patched in isolation because npm cannot
# reconcile its own package manifest. pnpm is pinned to a release with a fixed
# bundled tar dependency.
RUN apk add --no-cache build-base pkgconfig cairo-dev nodejs npm \
  && npm install -g npm@12.0.2 pnpm@11.23.0 \
  && rm -rf /tmp/tar-patch \
  && mkdir -p /tmp/tar-patch \
  && npm --prefix /tmp/tar-patch install --omit=dev --ignore-scripts \
    tar@7.5.21 brace-expansion@5.0.9 ip-address@10.3.1 \
  && cp -a /tmp/tar-patch/node_modules/. /usr/local/lib/node_modules/npm/node_modules/ \
  && rm -rf /tmp/tar-patch \
  && pnpm install --frozen-lockfile \
  && apk del npm

FROM ui AS hyperglass
WORKDIR /opt/hyperglass
# Install the pinned dependency set from the lockfile (the single source of
# truth), then the package itself without re-resolving dependencies. The lock
# includes the UI extra required by this full application image.
RUN pip3 install --no-cache-dir --no-deps -r requirements.lock \
  && pip3 install --no-cache-dir -e . --no-deps \
  && rm -rf /root/.cache/pip \
    /usr/local/lib/python3.13/site-packages/pip \
    /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
    /usr/local/bin/pip /usr/local/bin/pip3

EXPOSE ${HYPERGLASS_PORT}
CMD ["python3", "-m", "hyperglass.console", "start"]
