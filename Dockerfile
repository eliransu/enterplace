# Gantry Enterprise: the self-hosted product as one static binary, run as a user with no privileges, nothing else in
# the image. Build from the folder that holds both repositories:
#   docker buildx build -f gantry-enterprise/Dockerfile -t gantry-enterprise:local .
#
# Run:
#   docker run --rm -p 127.0.0.1:8080:8080 \
#     -v "$PWD/gantry.policy.yaml:/etc/gantry/gantry.policy.yaml:ro" \
#     -v gantry-data:/var/lib/gantry \
#     -e OPENAI_PROVIDER_KEY gantry-enterprise:local
# The policy file must say `audit: { path: /var/lib/gantry/gantry-audit.jsonl }`: /etc/gantry is read-only.
# `node` (a gateway managed by the hosted control plane) is still in the binary; it is no longer the default.
# Every open source `gantry` command runs from the same binary: docker run --rm <image> audit verify <file>.

FROM rust:1.88-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY gantry ./gantry
COPY gantry-enterprise ./gantry-enterprise
# Paths in the binary do not name the build machine.
ENV RUSTFLAGS="--remap-path-prefix=/src=. --remap-path-prefix=/usr/local/cargo=cargo"
# A static binary needs no C library in the final image, and TLS roots are compiled in, so no certificates either.
RUN cd gantry-enterprise && cargo build --release --locked \
 && mkdir -p /out/var/lib/gantry /out/etc/gantry && cp target/release/gantry-enterprise /out/gantry-enterprise

FROM scratch
COPY --from=build /out/gantry-enterprise /gantry-enterprise
# The audit log's folder belongs to the user Gantry runs as. Everything else is read-only to it.
COPY --from=build --chown=65532:65532 /out/var/lib/gantry /var/lib/gantry
COPY --from=build /out/etc/gantry /etc/gantry
# The Helm chart and the Terraform modules for this exact version, so a customer needs the registry and nothing else:
#   docker create --name gantry-files <image> && docker cp gantry-files:/deploy ./gantry-deploy && docker rm gantry-files
COPY --from=build /src/gantry-enterprise/deploy/helm /deploy/helm
COPY --from=build /src/gantry-enterprise/deploy/terraform /deploy/terraform
USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/gantry"]
ENTRYPOINT ["/gantry-enterprise"]
CMD ["serve", "/etc/gantry/gantry.policy.yaml", "--listen", "0.0.0.0:8080"]
