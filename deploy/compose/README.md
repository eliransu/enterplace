# Gantry with Docker Compose

The Compose file, the `.env` file and the trial override live in one place: the Docker guide,
https://gantry-docs.eliran.me/deploy/docker/ (`docs/src/content/docs/deploy/docker.mdx`). A customer copies them
from the page into an empty folder and runs the published image; nothing is cloned or built.

## Test

`test/run.sh <path to docker.mdx>` does what the guide says, in an empty folder: it writes the three files from the
page's blocks, fills in `.env`, starts the stack with the stand-in provider, issues a key with
`docker compose run --rm gantry key new`, makes a governed call, checks that a call without a key gets 401 and runs
`audit verify`. `GANTRY_IMAGE` pins the image. The `compose` job in `.github/workflows/deploy-targets.yml` runs it on every
change.
