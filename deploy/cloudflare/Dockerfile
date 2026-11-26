# The Enterplace image with your policy in it. `wrangler deploy` builds this for linux/amd64 and pushes it to your
# account's registry; ENTERPLACE_IMAGE comes from image_vars in wrangler.jsonc. The image is public: no login.
ARG ENTERPLACE_IMAGE=ghcr.io/eliransu/enterplace:0.3.0
FROM ${ENTERPLACE_IMAGE}
COPY --chmod=0644 enterplace.policy.yaml /etc/enterplace/enterplace.policy.yaml
