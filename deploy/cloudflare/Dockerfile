# The Gantry image with your policy in it. `wrangler deploy` builds this for linux/amd64 and pushes it to your
# account's registry; GANTRY_IMAGE comes from image_vars in wrangler.jsonc. Pull access to it is needed once, where
# you run wrangler: docker login ghcr.io.
ARG GANTRY_IMAGE=ghcr.io/ggantry/gantry-enterprise:0.1.0
FROM ${GANTRY_IMAGE}
COPY gantry.policy.yaml /etc/gantry/gantry.policy.yaml
