# Quickstart

Two ways to run Gantry: build the binary from source, or build and run the container image. Neither is published to a package registry yet, so both start from the source tree.

## From source

You need Rust 1.88 (the repository pins it in `rust-toolchain.toml`, so `rustup` installs it on first build).

```bash
cargo build --release
```

The binary is `target/release/gantry`. The commands below assume it is on your `PATH`.

### 1. Write a policy file

Save this as `gantry.policy.yaml`:

```yaml
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_PROVIDER_KEY
    models: [gpt-4o-mini, gpt-4o]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [gpt-4o-mini]
  - name: everyone-else
    principals: { any: true }
    models: []
```

The provider key is never in this file. `key_env` names the environment variable that holds it.

### 2. Check it

```bash
gantry check gantry.policy.yaml
```

```text
gantry.policy.yaml is valid: 2 rules, 0 keys, 1 provider: openai (openai) at https://api.openai.com.
```

A mistake is named with its file, line and the fix. See [Policy file](policy.html) for every message.

### 3. Make a key

```bash
gantry key new maya.cohen --team payments
```

The key (`gantry_` followed by 64 hex characters) is printed once. Only its SHA-256 is written to `gantry.keys.yaml`, which is created readable by its owner only. See [Keys](keys.html).

### 4. Serve

```bash
OPENAI_PROVIDER_KEY=... gantry serve gantry.policy.yaml
```

```text
gantry 0.0.1 listening on http://127.0.0.1:8080
Console: http://127.0.0.1:8080/console (sign in with an admin key)
Audit log: gantry-audit.jsonl is new. The chain starts at record 1.
2 rules, 1 key, 1 provider: openai (openai) at https://api.openai.com.
```

Gantry listens on `127.0.0.1:8080` unless `--listen host:port` says otherwise. It refuses to start if a provider's `key_env` variable is not set.

### 5. Send a request

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $GANTRY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello."}]}'
```

The answer is the provider's, with an `X-Gantry-Decision` header added. Ask for `gpt-4o` with the same key and the request is refused with `model_not_allowed`, because the `payments-team` rule lists only `gpt-4o-mini`.

From an OpenAI SDK, point its base URL at Gantry's `/v1` and give it the Gantry key. The SDKs read both from the environment, which is what `gantry key new` prints:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=gantry_...
```

```python
from openai import OpenAI
client = OpenAI()  # reads OPENAI_BASE_URL and OPENAI_API_KEY
print(client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "Say hello."}]).choices[0].message.content)
print([m.id for m in client.models.list()])  # the models your rule allows
```

```js
import OpenAI from "openai";
const client = new OpenAI(); // reads OPENAI_BASE_URL and OPENAI_API_KEY
const answer = await client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Say hello." }] });
console.log(answer.choices[0].message.content);
```

A refusal reaches the SDK as an API error whose message carries the cause and the decision ID. For Claude Code, see [Claude Code](claude-code.html).

### 6. Verify the audit log

```bash
gantry audit verify gantry-audit.jsonl
```

```text
gantry-audit.jsonl: 2 records in an unbroken chain from record 1 to record 2.
Last hash: 1ae338b7...
Records removed from the end leave the chain unbroken. To rule that out, compare this count and hash with a copy kept somewhere else.
```

## As a container

The image holds one static binary and nothing else, runs as user 65532, and is {{IMAGE_SIZE}} (measured by `scripts/release.sh image` for this release). It reads the policy and keys files from `/etc/gantry` and writes the audit log to a volume at `/var/lib/gantry`.

### Build the image

```bash
scripts/release.sh image     # tags gantry:0.0.1 and gantry:local
scripts/release.sh smoke     # runs it against a local mock and times the first governed request
```

The build uses the official `rust:1.88-alpine` image and produces a static musl binary. TLS roots are compiled in, so the image needs no certificate files.

### Write the policy for the container

The audit log must go on the volume, because `/etc/gantry` is mounted read-only. Add this line to `gantry.policy.yaml`:

```yaml
audit: { path: /var/lib/gantry/gantry-audit.jsonl }
```

### Make a key with the image

```bash
mkdir -p keys
docker run --rm -v "$PWD/keys:/work" -w /work --user "$(id -u)" \
  gantry:local key new maya.cohen --team payments --keys /work/gantry.keys.yaml
```

### Run it

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD/gantry.policy.yaml:/etc/gantry/gantry.policy.yaml:ro" \
  -v "$PWD/keys:/etc/gantry/keys" \
  -v gantry-audit:/var/lib/gantry \
  -e OPENAI_PROVIDER_KEY \
  gantry:local \
  serve /etc/gantry/gantry.policy.yaml --keys /etc/gantry/keys/gantry.keys.yaml --listen 0.0.0.0:8080
```

The keys file sits in a folder mounted writable, not as a read-only file: issuing and revoking a key from the console or the admin API (`POST /admin/keys`, `DELETE /admin/keys/<prefix>`, the revoke path in [Operations](operations.md)) writes to it, and Gantry writes a new key through a temporary file in the same folder. With a read-only mount those calls fail with `keys_file`.

Inside the container Gantry listens on `0.0.0.0:8080`, so the port mapping decides who can reach it. Keep `127.0.0.1:` in front of the port unless TLS sits in front of Gantry: keys travel over plain HTTP.

On Linux, `gantry.keys.yaml` is created readable by its owner only, and the container runs as user 65532. Give that user the folder and the file (for example `sudo chown -R 65532 keys`) before mounting it. This was tested on Docker Desktop for macOS, where bind mounts do not enforce the owner.

To verify the audit log in the running container:

```bash
docker exec <container> /gantry audit verify /var/lib/gantry/gantry-audit.jsonl
```

### Linux release tarballs

```bash
scripts/release.sh linux
```

This builds the image for `linux/amd64` and `linux/arm64` with `docker buildx` and takes the binary out of each into `dist/gantry-0.0.1-<src>-x86_64-unknown-linux-musl.tar.gz` and `dist/gantry-0.0.1-<src>-aarch64-unknown-linux-musl.tar.gz`, each with a `.sha256` file and a `.BUILD` file. `<src>` is the hash of the sources the binary was built from, which `gantry version` also prints (`gantry 0.0.1 (src 3f9a1c2b4d5e, built 2026-11-13)`): name it in a bug report. Older tarballs of the same target are deleted before a build. `scripts/release.sh tarball` packs the binary for the machine you are on.
