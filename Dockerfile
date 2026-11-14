# Gantry as a container: one static binary, run as a user with no privileges, nothing else in the image.
# The binary is the enterprise build (enterprise/, under its own license). Without a license key it is the open source
# gateway; a valid key in GANTRY_LICENSE unlocks the paid features. Every open source command runs from it too.
# Build: scripts/release.sh image, or `docker build -t gantry:local .`
#
# Run with nothing but a provider key: the first start writes an observe-mode policy and an admin key (printed once)
# on the volume, and later starts serve them (`gantry start --container`):
#   docker run -p 127.0.0.1:8080:8080 -v gantry-data:/var/lib/gantry -e OPENAI_API_KEY ghcr.io/ggantry/gantry
# Or with your own policy, served as it is:
#   docker run --rm -p 127.0.0.1:8080:8080 \
#     -v "$PWD/gantry.policy.yaml:/etc/gantry/gantry.policy.yaml:ro" \
#     -v gantry-data:/var/lib/gantry \
#     -e OPENAI_PROVIDER_KEY gantry:local
# The policy file must say `audit: { path: /var/lib/gantry/gantry-audit.jsonl }`: /etc/gantry is read-only.
# Admin commands use the same binary: docker run --rm <image> audit verify <file>.

FROM rust:1.88-alpine AS build
RUN apk add --no-cache musl-dev
# cargo-auditable writes the binary's exact crate list into the binary itself. The image is FROM scratch, with no
# package database, so without it syft (the SBOM), Grype (the image scan) and `cargo audit bin` see no dependencies.
RUN cargo install cargo-auditable --locked --version 0.7.5
WORKDIR /src
COPY . .
# Reproducible: the release pipeline passes the commit's time, and paths in the binary do not name this machine.
# Two builds of one commit give the same binary (scripts/release.sh reproduce checks it).
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    RUSTFLAGS="--remap-path-prefix=/src=. --remap-path-prefix=/usr/local/cargo=cargo"
# A static binary needs no C library in the final image. TLS roots are compiled in, so it needs no certificates either.
RUN cargo auditable build --release --locked -p gantry-enterprise \
 && mkdir -p /out/var/lib/gantry /out/etc/gantry \
 && cp target/release/gantry-enterprise /out/gantry

FROM scratch
COPY --from=build /out/gantry /gantry
# The audit log's folder belongs to the user Gantry runs as. Everything else is read-only to it.
COPY --from=build --chown=65532:65532 /out/var/lib/gantry /var/lib/gantry
COPY --from=build /out/etc/gantry /etc/gantry
# The Helm chart, the Terraform modules and the Cloudflare template for this exact version, so a customer needs the
# registry and nothing else:
#   docker create --name gantry-files <image> && docker cp gantry-files:/deploy ./gantry-deploy && docker rm gantry-files
COPY --from=build /src/deploy/helm /deploy/helm
COPY --from=build /src/deploy/terraform /deploy/terraform
COPY --from=build /src/deploy/cloudflare /deploy/cloudflare
USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/gantry"]
ENTRYPOINT ["/gantry"]
# Serves /etc/gantry/gantry.policy.yaml when one is mounted (as `serve` always did), else the policy an earlier start
# wrote on the volume, else writes one from the provider keys in the environment.
CMD ["start", "--container"]
