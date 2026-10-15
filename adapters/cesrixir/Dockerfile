# The cesrixir adapter's image. bin/build builds it and tags it with a digest of the adapter's
# sources; bin/kcs-adapter-cesrixir runs it. See README.md.
#
# Both stages use the official elixir image, pinned by digest (tag 1.19.5-otp-28-slim, pushed
# 2026-09-02). cesrixir's mix.exs needs Elixir ~> 1.19.
ARG ELIXIR_IMAGE=elixir:1.19.5-otp-28-slim@sha256:597474ac81f0d0bfa4d67546c2591a033315a2b9e6ab2f1a22824af9c913066a

FROM ${ELIXIR_IMAGE} AS deps
# The slim image has no CA certificates, and fetching from hex.pm needs them. The packages are
# checked against mix.lock's checksums whatever the transport.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
ENV MIX_HOME=/opt/mix HEX_HOME=/opt/hex
WORKDIR /src
RUN mix local.hex --force && mix local.rebar --force
COPY mix.exs mix.lock ./
RUN mix deps.get --check-locked

FROM deps AS build
COPY config config
COPY lib lib
RUN MIX_ENV=prod mix compile --warnings-as-errors && MIX_ENV=prod mix escript.build

# Runs the tests with the coverage gate, and the stdio test against the escript built above.
# --build-context suite=<repository root> supplies the protocol schema and the feature vocabulary.
FROM build AS test
COPY test test
COPY --from=suite schema/adapter-protocol.schema.json /suite/schema/
COPY --from=suite profiles/features.json /suite/profiles/
ENV KCS_SUITE=/suite KCS_ESCRIPT=/src/kcs-adapter-cesrixir
RUN MIX_ENV=test mix test --cover

FROM ${ELIXIR_IMAGE} AS adapter
COPY --from=build /src/kcs-adapter-cesrixir /usr/local/bin/kcs-adapter-cesrixir
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/kcs-adapter-cesrixir"]
