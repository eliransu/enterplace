# Gantry as a container: one static binary, run as a user with no privileges, nothing else in the image.
# Build: scripts/release.sh, or `docker build -t gantry:local .`
#
# Run:
#   docker run --rm -p 127.0.0.1:8080:8080 \
#     -v "$PWD/gantry.policy.yaml:/etc/gantry/gantry.policy.yaml:ro" \
#     -v "$PWD/keys:/etc/gantry/keys" \
#     -v gantry-audit:/var/lib/gantry \
#     -e OPENAI_PROVIDER_KEY gantry:local \
#     serve /etc/gantry/gantry.policy.yaml --keys /etc/gantry/keys/gantry.keys.yaml --listen 0.0.0.0:8080
# The policy file must say `audit: { path: /var/lib/gantry/gantry-audit.jsonl }`: /etc/gantry is read-only.
# The keys folder is writable because the console and the admin API issue and revoke keys there; a read-only keys file makes both fail.

FROM rust:1.88-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# A static binary needs no C library in the final image. TLS roots are compiled in, so it needs no certificates either.
RUN cargo build --release --locked -p gantry-cli \
 && mkdir -p /out/var/lib/gantry /out/etc/gantry \
 && cp target/release/gantry /out/gantry

FROM scratch
COPY --from=build /out/gantry /gantry
# The audit log's folder belongs to the user Gantry runs as. Everything else is read-only to it.
COPY --from=build --chown=65532:65532 /out/var/lib/gantry /var/lib/gantry
COPY --from=build /out/etc/gantry /etc/gantry
USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/gantry"]
ENTRYPOINT ["/gantry"]
CMD ["serve", "/etc/gantry/gantry.policy.yaml", "--listen", "0.0.0.0:8080"]
