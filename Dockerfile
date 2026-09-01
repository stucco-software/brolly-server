# Build.
#
# The whole workspace is copied rather than just `server/`: the binary depends
# on every adapter, and a partial copy fails at link time rather than at COPY,
# which is a much worse place to discover it.
FROM rust:1-bookworm AS build
WORKDIR /src

# oxigraph builds RocksDB from source, which needs a C++ toolchain and clang.
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-dev cmake \
 && rm -rf /var/lib/apt/lists/*

COPY . .

# `--locked` so an image build cannot quietly resolve different versions than
# the tests ran against.
RUN cargo build --release --locked --bin brolly-server --bin brolly-admin

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Not root. The data directory is the only thing it needs to write.
RUN useradd --system --create-home --uid 10001 brolly
COPY --from=build /src/target/release/brolly-server /usr/local/bin/
COPY --from=build /src/target/release/brolly-admin /usr/local/bin/
COPY --from=build /src/server/static /srv/static

ENV BROLLY_STATIC_DIR=/srv/static \
    BROLLY_DATA_DIR=/var/lib/brolly \
    BROLLY_PORT=3000
RUN mkdir -p /var/lib/brolly && chown brolly:brolly /var/lib/brolly
USER brolly
VOLUME ["/var/lib/brolly"]
EXPOSE 3000

CMD ["brolly-server"]
