# The managed gateway: gantry-enterprise as a node of the control plane, for Gantry's hosted service.
# Build from the folder that holds both repositories:
#   docker buildx build --platform linux/amd64 -f gantry-enterprise/Dockerfile -t gantry-enterprise:local .
FROM rust:1.88-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY gantry ./gantry
COPY gantry-enterprise ./gantry-enterprise
RUN cd gantry-enterprise && cargo build --release --locked \
 && mkdir -p /out/var/lib/gantry && cp target/release/gantry-enterprise /out/gantry-enterprise

FROM scratch
COPY --from=build /out/gantry-enterprise /gantry-enterprise
COPY --from=build --chown=65532:65532 /out/var/lib/gantry /var/lib/gantry
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/gantry-enterprise"]
CMD ["node", "--control-plane", "https://gantry-control.eliran.me", "--dir", "/var/lib/gantry", "--listen", "0.0.0.0:8080", "--interval", "5"]
