# The Gantry image with your policy in it. `wrangler deploy` builds this for linux/amd64 and pushes it to your
# account's registry; GANTRY_IMAGE comes from image_vars in wrangler.jsonc. The image is public: no login.
ARG GANTRY_IMAGE=ghcr.io/eliransu/gantry:0.1.0
FROM ${GANTRY_IMAGE}
COPY --chmod=0644 gantry.policy.yaml /etc/gantry/gantry.policy.yaml
