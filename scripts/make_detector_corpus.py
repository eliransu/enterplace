"""Writes crates/gantry-core/tests/corpus/gantry-detectors-v1.jsonl, the labelled corpus the built-in detectors are
measured on (crates/gantry-core/tests/detector_corpus.rs, docs/src/content/docs/governance/guardrails.mdx).

Usage: python3 scripts/make_detector_corpus.py
The output is fixed by the seed below, so running this again writes the same file. A new corpus version is a new
file name: published numbers name the version they were measured on, so v1 is never edited to move them.
Every value is synthetic (random with a valid or deliberately invalid checksum, reserved fictional phone ranges,
RFC 2606 mail domains) or a publicly documented example value (AWS's AKIAIOSFODNN7EXAMPLE, card networks' published
test numbers). Labels are what a careful reader would call each value, written before the detectors were run.
Standard library only.
"""
import base64, json, pathlib, random, string

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crates" / "gantry-core" / "tests" / "corpus" / "gantry-detectors-v1.jsonl"
R = random.Random(20261113)

UP = string.ascii_uppercase
ALNUM = string.ascii_letters + string.digits
UPNUM = UP + string.digits
HEX = "0123456789abcdef"
B64 = string.ascii_letters + string.digits + "+/"
B64URL = string.ascii_letters + string.digits + "-_"

rows = []


def add(target, text, expect):
    rows.append({"target": target, "text": text, "expect": sorted(expect)})


def pos(kind, text, n=1):
    add(kind, text, [kind] * n)


def neg(kind, text):
    add(kind, text, [])


def rnd(alphabet, n):
    return "".join(R.choice(alphabet) for _ in range(n))


# Contexts: the same value as it shows up in prose, chat, code, logs and JSON.
def contexts(label, value, key):
    return [
        f"Here is the {label} you asked for: {value}",
        f"User: can you check why this fails? my {label} is {value} thanks",
        f'{key} = "{value}"',
        f"2026-03-04T10:22:01Z INFO worker=billing-7 {key}={value} status=ok",
        json.dumps({key: value, "env": "staging"}),
        f"export {key.upper()}={value}",
        f"- {label}: {value}\n- owner: platform team",
        f"Assistant: I found `{value}` in the config, rotate it before you commit.",
    ]


def b64lines(n, width=64):
    return "\n".join(rnd(B64, width) for _ in range(n))


# --------------------------------------------------------------------------------------------------------------
# private_key
# --------------------------------------------------------------------------------------------------------------
pem_types = ["RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED ", ""]
for i in range(36):
    t = pem_types[i % len(pem_types)]
    block = f"-----BEGIN {t}PRIVATE KEY-----\n{b64lines(3 + i % 4)}\n-----END {t}PRIVATE KEY-----"
    shapes = [
        block,
        f"Here's the deploy key, please add it to the runner:\n{block}",
        json.dumps({"type": "service_account", "private_key": block + "\n", "client_id": "ci-runner"}),
        f'PRIVATE_KEY="{block}"',
        f"tls:\n  key: |\n    " + block.replace("\n", "\n    "),
        f"User: why does ssh reject this?\n```\n{block}\n```",
    ]
    pos("private_key", shapes[i % len(shapes)])
for i in range(4):
    block = f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{b64lines(4)}\n={rnd(B64, 4)}\n-----END PGP PRIVATE KEY BLOCK-----"
    pos("private_key", block if i % 2 == 0 else f"exported with gpg --export-secret-keys:\n{block}")
pos("private_key", f"two keys:\n-----BEGIN RSA PRIVATE KEY-----\n{b64lines(2)}\n-----END RSA PRIVATE KEY-----\nand\n"
    f"-----BEGIN EC PRIVATE KEY-----\n{b64lines(2)}\n-----END EC PRIVATE KEY-----", 2)

pk_neg = [
    f"-----BEGIN PUBLIC KEY-----\n{b64lines(4)}\n-----END PUBLIC KEY-----",
    f"-----BEGIN CERTIFICATE-----\n{b64lines(6)}\n-----END CERTIFICATE-----",
    f"-----BEGIN CERTIFICATE REQUEST-----\n{b64lines(4)}\n-----END CERTIFICATE REQUEST-----",
    f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{b64lines(4)}\n-----END PGP PUBLIC KEY BLOCK-----",
    f"-----BEGIN PGP SIGNATURE-----\n\n{b64lines(2)}\n-----END PGP SIGNATURE-----",
    f"-----BEGIN PGP MESSAGE-----\n\n{b64lines(3)}\n-----END PGP MESSAGE-----",
    f"-----BEGIN RSA PUBLIC KEY-----\n{b64lines(3)}\n-----END RSA PUBLIC KEY-----",
    f"-----BEGIN X509 CRL-----\n{b64lines(3)}\n-----END X509 CRL-----",
    f"-----BEGIN DH PARAMETERS-----\n{b64lines(3)}\n-----END DH PARAMETERS-----",
    f"-----BEGIN EC PARAMETERS-----\n{b64lines(1, 12)}\n-----END EC PARAMETERS-----",
    f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ{rnd(B64, 200)} dev@laptop",
    f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{rnd(B64, 43)} ci@runner",
    "-----END RSA PRIVATE KEY-----",
    "Never paste a private key into a chat, rotate it if you did.",
    "private_key_path: /etc/gantry/tls/server.key",
    "ansible-playbook site.yml --private-key ./deploy.pem",
    "The file should start with BEGIN RSA PRIVATE KEY between five dashes.",
    'openssl genpkey -algorithm ed25519 -out key.pem && openssl pkey -in key.pem -pubout',
    "ssh-keygen -t ed25519 -C ci@runner -f ~/.ssh/id_ed25519",
    "Error: error:1E08010C:DECODER routines::unsupported (no PRIVATE KEY found in input)",
    '{"kty":"OKP","crv":"Ed25519","x":"' + rnd(B64URL, 43) + '"}',
    "-----BEGIN NEW CERTIFICATE REQUEST-----",
    "----- BEGIN -----\nnotes from the key ceremony\n----- END -----",
    "-----BEGIN SSH2 PUBLIC KEY-----\nComment: \"ci\"\n" + b64lines(3) + "\n-----END SSH2 PUBLIC KEY-----",
    "keyFile := flag.String(\"private-key\", \"\", \"path to the PEM private key\")",
    "PRIVATE KEY rotation is due on the first Monday of each quarter.",
    "-----BEGIN PKCS7-----\n" + b64lines(3) + "\n-----END PKCS7-----",
    "-----BEGIN TRUSTED CERTIFICATE-----\n" + b64lines(3) + "\n-----END TRUSTED CERTIFICATE-----",
    "grep -r 'PRIVATE KEY' . returned nothing, good.",
    "Use `-----BEGIN` markers only in test fixtures that the scanner allowlists.",
]
for text in pk_neg:
    neg("private_key", text)
for i in range(10):
    neg("private_key", f"-----BEGIN CERTIFICATE-----\n{b64lines(5)}\n-----END CERTIFICATE-----\n# chain {i + 1}")

# --------------------------------------------------------------------------------------------------------------
# aws_access_key
# --------------------------------------------------------------------------------------------------------------
aws = ["AKIAIOSFODNN7EXAMPLE"] + [R.choice(["AKIA", "AKIA", "AKIA", "ASIA"]) + rnd(UPNUM, 16) for _ in range(39)]
for i, key in enumerate(aws):
    shapes = [
        f"[default]\naws_access_key_id = {key}\naws_secret_access_key = {rnd(ALNUM + '/+', 40)}",
        f"export AWS_ACCESS_KEY_ID={key}",
        f'session = boto3.Session(aws_access_key_id="{key}", region_name="eu-west-1")',
        json.dumps({"AccessKeyId": key, "Expiration": "2026-03-04T11:22:01Z"}),
        f"User: the pipeline prints {key} in the build log, is that bad?",
        f"2026-03-04 10:22:01 WARN s3 upload denied for key {key} on bucket assets-prod",
        f"aws_access_key_id: {key}",
        f"Use {key} with the read-only role.",
    ]
    pos("aws_access_key", shapes[i % len(shapes)])
aws_neg = [
    "AIDAJQABLZS4A3QDU576",  # an IAM user's unique ID from AWS's documentation, not a credential
    "AROADBQP57FF2AEXAMPLE",
    "ANPAJ2UCCR6DPCEXAMPLE",
    "Access key IDs start with AKIA for long-term keys and ASIA for temporary ones.",
    "akiaiosfodnn7example",
    "AKIAIOSFODNN7EXAMPL",
    "AKIAIOSFODNN7EXAMPLEX",
    "arn:aws:iam::123456789012:user/build-bot",
    "The ASIA region bucket is assets-ap-southeast-1.",
    "AKIA_PLACEHOLDER_REPLACE_ME",
    "export AWS_ACCESS_KEY_ID=$(vault read -field=key aws/creds/ci)",
    "aws_access_key_id = ${AWS_ACCESS_KEY_ID}",
    "AKIA****************",
    "AKIA-IOSF-ODNN-7EXA-MPLE",
    "x-amz-request-id: 4442587FB7D0A2F9",
    "x-amz-id-2: vlR7PnpV2Ce81l0PRw6jlUpck7Jo5ZsQjryTjKlc5aLWGVHPZLj5NeC6qMa0emYBDXOo6QBU0Wo=",
    "ETag: \"9b2cf535f27731c974343645a3985328\"",
    "CloudFront distribution E2QWRUHAPOMQZL is deployed.",
]
for text in aws_neg:
    neg("aws_access_key", text)
for _ in range(22):
    prefix = R.choice(["AIDA", "AROA", "ANPA", "AGPA", "AIPA", "ANVA", "APKA", "E1", "I-0"])
    neg("aws_access_key", f"resource id {prefix}{rnd(UPNUM, 16)} created")

# --------------------------------------------------------------------------------------------------------------
# github_token
# --------------------------------------------------------------------------------------------------------------
gh = [f"gh{R.choice('pousr')}_{rnd(ALNUM, 36)}" for _ in range(32)]
gh += [f"github_pat_11{rnd(UPNUM, 20)}_{rnd(ALNUM, 59)}" for _ in range(8)]
for i, token in enumerate(gh):
    shapes = [
        f"git remote set-url origin https://{token}@github.com/acme/infra.git",
        f"export GITHUB_TOKEN={token}",
        f'headers = {{"Authorization": "Bearer {token}"}}',
        json.dumps({"github": {"token": token}}),
        f"User: I set GH_TOKEN to {token} and gh auth status still fails",
        f"2026-03-04T10:22:01Z DEBUG fetch repo with token={token}",
        f"//npm.pkg.github.com/:_authToken={token}",
        f"echo {token} | docker login ghcr.io -u ci --password-stdin",
    ]
    pos("github_token", shapes[i % len(shapes)])
gh_neg = [
    "Personal access tokens start with ghp_ and fine-grained ones with github_pat_.",
    f"ghp_{rnd(ALNUM, 35)}",
    f"ghx_{rnd(ALNUM, 36)}",
    f"gh_{rnd(ALNUM, 36)}",
    f"github_pat_{rnd(ALNUM, 21)}",
    "export GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}",
    "ghp_XXXXXXXXXXXX",
    "gho_ is the prefix of an OAuth access token.",
    "uses: actions/checkout@v4",
    "https://github.com/acme/infra/pull/4821",
    "github_pat_ tokens can be scoped to one repository.",
    "token: ghp_<your token here>",
]
for text in gh_neg:
    neg("github_token", text)
for _ in range(16):
    neg("github_token", f"commit {rnd(HEX, 40)}\nMerge pull request #{R.randint(100, 9999)} from acme/fix-ci")
for _ in range(12):
    neg("github_token", f"https://github.com/acme/infra/blob/{rnd(HEX, 40)}/deploy/main.tf#L{R.randint(1, 400)}")

# --------------------------------------------------------------------------------------------------------------
# slack_token
# --------------------------------------------------------------------------------------------------------------
slack = []
for i in range(36):
    t = "bpaor"[i % 5]
    slack.append(f"xox{t}-{R.randint(10**10, 10**12)}-{R.randint(10**11, 10**13)}-{rnd(ALNUM, 24)}")
slack += [f"xoxe-1-{rnd(ALNUM, 140)}" for _ in range(2)]  # refresh tokens of rotating Slack apps
slack += [f"xoxe.xoxp-1-{rnd(ALNUM, 140)}" for _ in range(2)]
for i, token in enumerate(slack):
    shapes = [
        f"SLACK_BOT_TOKEN={token}",
        f'client = WebClient(token="{token}")',
        json.dumps({"slack": {"bot_token": token, "channel": "C0123ABCD"}}),
        f"User: our bot stopped posting, token is {token}",
        f"2026-03-04T10:22:01Z ERROR slack post failed token={token} err=invalid_auth",
        f"curl -H 'Authorization: Bearer {token}' https://slack.com/api/auth.test",
        f"slack:\n  token: {token}",
        f"Rotate {token} today, it was in the screenshot.",
    ]
    pos("slack_token", shapes[i % len(shapes)])
slack_neg = [
    "xoxo, see you tomorrow",
    "Bot tokens start with xoxb- and user tokens with xoxp-.",
    "SLACK_BOT_TOKEN=xoxb-your-token",
    "xoxb-1234",
    f"xoxz-{R.randint(10**10, 10**12)}-{rnd(ALNUM, 24)}",
    "token: xoxb-****",
    "slack_token: ${SLACK_BOT_TOKEN}",
    "channel C0123ABCD and team T0123ABCD",
    "XOXO GOSSIP GIRL",
    "Message from U024BE7LH in #deploys",
    "Hugs and kisses xoxoxo",
    "xox-b is not a token prefix",
]
for text in slack_neg:
    neg("slack_token", text)
for _ in range(28):
    neg("slack_token", f"https://acme.slack.com/archives/C{rnd(UPNUM, 8)}/p{R.randint(10**15, 10**16)}")

# --------------------------------------------------------------------------------------------------------------
# gantry_key
# --------------------------------------------------------------------------------------------------------------
for i in range(40):
    key = f"gantry_{rnd(HEX, 64)}"
    shapes = [
        f"export GANTRY_KEY={key}",
        f"curl -H 'Authorization: Bearer {key}' http://127.0.0.1:8787/v1/models",
        json.dumps({"api_key": key, "base_url": "http://127.0.0.1:8787/v1"}),
        f"User: my key {key} gets 401 from the gateway",
        f'client = OpenAI(api_key="{key}", base_url="http://127.0.0.1:8787/v1")',
        f"ANTHROPIC_AUTH_TOKEN={key}",
        f"key: {key}",
        f"Revoke {key}, it was in the wiki.",
    ]
    pos("gantry_key", shapes[i % len(shapes)])
gk_neg = [
    f"gantry_{rnd(HEX, 63)}",
    f"gantry_{rnd(HEX, 65)}",
    f"gantry_{rnd(HEX, 64).upper()}",
    "gantry_core::guard::scan(&parts)",
    "use gantry_server::serve;",
    "gantry_check_examples",
    "GANTRY_KEY=gantry_your_key_here",
    "pip install gantry_sdk",
    f"gantry-{rnd(HEX, 64)}",
    "keys look like gantry_ followed by 64 hex digits",
]
for text in gk_neg:
    neg("gantry_key", text)
for _ in range(15):
    neg("gantry_key", f"sha256:{rnd(HEX, 64)}")
for _ in range(15):
    neg("gantry_key", f"{rnd(HEX, 64)}  gantry-x86_64-unknown-linux-gnu.tar.gz")

# --------------------------------------------------------------------------------------------------------------
# jwt
# --------------------------------------------------------------------------------------------------------------
def b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


for i in range(40):
    header = {"alg": R.choice(["HS256", "RS256", "ES256"]), "typ": "JWT"}
    claims = {"sub": f"user-{R.randint(1000, 99999)}", "iat": 1772600000 + R.randint(0, 10**6), "scope": "read"}
    sig = "" if i == 39 else rnd(B64URL, R.choice([43, 86, 342]))
    token = f"{b64u(header)}.{b64u(claims)}.{sig}"
    shapes = [
        f"Authorization: Bearer {token}",
        f"Set-Cookie: session={token}; HttpOnly; Secure",
        json.dumps({"access_token": token, "token_type": "Bearer", "expires_in": 3600}),
        f"User: decode this for me {token}",
        f"curl -H \"Authorization: Bearer {token}\" https://api.example.com/v1/me",
        f"2026-03-04T10:22:01Z DEBUG auth ok jwt={token}",
        f'const token = "{token}";',
        f"id_token: {token}",
    ]
    pos("jwt", shapes[i % len(shapes)])
jwt_neg = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "A JWT has three parts: header.payload.signature, each base64url.",
    "Authorization: Bearer <token>",
    "version 1.22.3.4",
    "eyJ is just {\" in base64",
    "jwt: ${JWT_TOKEN}",
    "eyJ...eyJ...sig",
    "a.b.c",
]
for text in jwt_neg:
    neg("jwt", text)
for _ in range(12):
    blob = b64u({"version": 3, "sources": [f"src/{rnd(string.ascii_lowercase, 6)}.ts"], "mappings": rnd(B64, 40)})
    neg("jwt", f"//# sourceMappingURL=data:application/json;base64,{blob}")
for _ in range(10):
    blob = base64.b64encode(json.dumps({"auths": {"registry.example.com": {"auth": rnd(B64, 24)}}}).encode()).decode()
    neg("jwt", f".dockerconfigjson: {blob}")
for _ in range(10):
    neg("jwt", f"{b64u({'kid': rnd(HEX, 8)})}.{rnd(B64URL, 30)}")

# --------------------------------------------------------------------------------------------------------------
# api_key (sk-...)
# --------------------------------------------------------------------------------------------------------------
keys = []
keys += [f"sk-{rnd(ALNUM, 48)}" for _ in range(10)]
keys += [f"sk-proj-{rnd(ALNUM + '-_', 156)}" for _ in range(10)]
keys += [f"sk-ant-api03-{rnd(ALNUM + '-_', 93)}AA" for _ in range(10)]
keys += [f"sk-or-v1-{rnd(HEX, 64)}" for _ in range(5)]
keys += [f"sk-{rnd(HEX, 32)}" for _ in range(5)]
for i, key in enumerate(keys):
    shapes = [
        f"export OPENAI_API_KEY={key}",
        f'client = OpenAI(api_key="{key}")',
        f"curl https://api.anthropic.com/v1/messages -H 'x-api-key: {key}'",
        json.dumps({"provider": "openai", "api_key": key}),
        f"User: is {key} still valid? I get 401",
        f"2026-03-04T10:22:01Z ERROR upstream 401 key={key}",
        f"ANTHROPIC_API_KEY={key}",
        f"Here is my key {key} please debug",
    ]
    pos("api_key", shapes[i % len(shapes)])
api_neg = [
    "OPENAI_API_KEY=sk-...",
    "sk-short",
    f"sk-{rnd(ALNUM, 19)}",
    "task-1234567890abcdefghijklmnop",
    "disk-usage-report-2026-03-04-final",
    "risk-assessment-template-for-vendors-v2",
    "import sklearn  # pip install scikit-learn",
    "<div class=\"sk-folding-cube\"></div>",
    "Slovak locale sk-SK is supported.",
    "https://news.example.com/2026/03/sk-hynix-hbm-supply-deal-with-partners",
    "https://news.example.com/2026/02/sk-telecom-quarterly-earnings-beat",
    "Keys start with sk- and are shown once.",
    "api_key: ${OPENAI_API_KEY}",
    "sk-ant-...",
    "asks-for-review-from-platform-team-members",
    "pk_test_TYooMQauvdEDq54NiTphI7jx",
    "the bucket is tasks-archive-eu-west-1-production",
]
for text in api_neg:
    neg("api_key", text)
for _ in range(23):
    neg("api_key", f"request_id=req_{rnd(ALNUM, 24)} trace={rnd(HEX, 32)}")

# --------------------------------------------------------------------------------------------------------------
# email_address
# --------------------------------------------------------------------------------------------------------------
first = ["maya", "noam", "alex", "sam", "dana", "lior", "jordan", "riley", "casey", "tal", "omer", "jamie"]
last = ["roe", "doe", "levi", "cohen", "smith", "garcia", "nguyen", "kim", "shapiro", "mizrahi"]
domains = ["example.com", "example.org", "example.net", "mail.example.com", "corp.example.co.il", "shop.example",
           "users.test", "eu.example.org"]
for i in range(40):
    f, l = R.choice(first), R.choice(last)
    local = R.choice([f"{f}.{l}", f"{f}{l}", f"{f}_{l}", f"{f}+invoices", f"{f[0]}{l}{R.randint(1, 99)}", f"{f}-{l}"])
    addr = f"{local}@{R.choice(domains)}"
    shapes = [
        f"Contact {addr} for access.",
        f"From: {f.title()} {l.title()} <{addr}>",
        json.dumps({"email": addr, "role": "admin"}),
        f"User: please send the report to {addr} by friday",
        f"2026-03-04T10:22:01Z INFO login ok user={addr}",
        f"<a href=\"mailto:{addr}\">write to us</a>",
        f"name,email\n{f.title()} {l.title()},{addr}",
        f"git config user.email {addr}",
    ]
    pos("email_address", shapes[i % len(shapes)])
email_neg = [
    "git clone git@github.com:acme/infra.git",
    "<img src=\"logo@2x.png\" srcset=\"logo@3x.png 3x\">",
    "npm install @types/node lodash@4.17.21",
    "docker pull nginx@sha256:" + rnd(HEX, 64),
    "ssh deploy@10.0.3.17",
    "Ping @channel about the outage",
    "user@localhost is the default in dev",
    "@app.route('/health')",
    "email: ${SMTP_USER}",
    "write to support at example dot com",
    "foo@bar",
    "the @ sign separates user and host",
    "postgres://app@db:5432/orders",
    "@acme/ui@2.3.1",
    "admin@192.168.1.1",
    "Twitter handle @gantry_ai",
]
for text in email_neg:
    neg("email_address", text)
for _ in range(12):
    neg("email_address", f"{rnd(string.ascii_lowercase, 6)}@{R.randint(1, 9)}.{R.randint(0, 30)}.{R.randint(0, 30)}")
for _ in range(12):
    neg("email_address", f"@{rnd(string.ascii_lowercase, 7)} thanks for the review!")

# --------------------------------------------------------------------------------------------------------------
# phone_number (fictional ranges: US 555-01xx, UK 07700 900xxx, AU 0491 570 xxx, FR 01 99 00 xx xx)
# --------------------------------------------------------------------------------------------------------------
phones = []
for _ in range(8):
    a, n = R.choice(["212", "415", "312", "617", "206"]), f"01{R.randint(0, 99):02d}"
    phones.append(R.choice([f"({a}) 555-{n}", f"{a}-555-{n}", f"{a}.555.{n}", f"+1 {a} 555 {n}", f"+1-{a}-555-{n}"]))
phones += [f"1-800-555-01{R.randint(0, 99):02d}" for _ in range(2)]
phones += [f"+44 7700 900{R.randint(0, 999):03d}" for _ in range(6)]
phones += [f"07700 900{R.randint(0, 999):03d}" for _ in range(3)]  # UK national format
phones += [f"+61 491 570 {R.randint(110, 159)}" for _ in range(4)]
phones += [f"0491 570 {R.randint(110, 159)}" for _ in range(2)]  # AU national format
phones += [f"+33 1 99 00 {R.randint(0, 99):02d} {R.randint(0, 99):02d}" for _ in range(3)]
phones += [f"+972-5{R.randint(0, 8)}-{R.randint(100, 999)}-{R.randint(1000, 9999)}" for _ in range(4)]
phones += [f"05{R.randint(0, 8)}-{R.randint(10**6, 10**7 - 1)}" for _ in range(4)]
phones += [f"+972 5{R.randint(0, 8)} {R.randint(100, 999)} {R.randint(1000, 9999)}" for _ in range(4)]
for i, phone in enumerate(phones):
    shapes = [
        f"Call me at {phone} after 5.",
        f"Phone: {phone}",
        json.dumps({"name": "front desk", "phone": phone}),
        f"User: the customer left {phone} as a callback number",
        f"2026-03-04T10:22:01Z INFO sms queued to={phone}",
        f"tel. {phone} (mobile)",
        f"Emergency contact: {phone}",
        f"Reach the on-call engineer on {phone}.",
    ]
    pos("phone_number", shapes[i % len(shapes)])
phone_neg = [
    "Released on 2026-03-04 at 10:22:01.",
    "Server 10.0.12.34 answered in 120 ms.",
    "Upgraded from v1.22.3 to v1.23.0",
    "ISBN 978-3-16-148410-0",
    "ZIP 94103-1234",
    "PO 4500012345",
    "+1 for this proposal",
    "page 12 of 345",
    "3 + 4 = 7",
    "Total: $1,234,567.89",
    "40.7128, -74.0060",
    "build 2026.03.04.1542",
    "Order #123-456-7890 has shipped.",
    "Invoice 2026-000-4412",
    "uptime 99.95% over 30 days",
    "chmod 0755 deploy.sh",
    "Tue, 04 Mar 2026 10:22:01 +0200",
    "Score: 3-2 after extra time",
    "Room 2.04, floor 3",
    "port 8787, pid 48213",
]
for text in phone_neg:
    neg("phone_number", text)
for _ in range(10):
    neg("phone_number", f"Order #{R.randint(100, 999)}-{R.randint(100, 999)}-{R.randint(1000, 9999)} is ready for pickup.")
for _ in range(10):
    neg("phone_number", f"latency p50={R.randint(10, 99)}.{R.randint(0, 9)}ms p99={R.randint(100, 999)}.{R.randint(0, 9)}ms")

# --------------------------------------------------------------------------------------------------------------
# credit_card (published test numbers of the card networks and payment processors)
# --------------------------------------------------------------------------------------------------------------
cards = ["4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556", "5555555555554444",
         "5105105105105100", "5200828282828210", "2223003122003222", "378282246310005", "371449635398431",
         "6011111111111117", "6011000990139424", "3530111333300000", "3566002020360505", "30569309025904",
         "38520000023237", "6200000000000005", "4000000000003220", "4000002500003155", "5454545454545454"]


def grouped(n, sep):
    if len(n) == 15:
        return f"{n[:4]}{sep}{n[4:10]}{sep}{n[10:]}"
    return sep.join(n[i:i + 4] for i in range(0, len(n), 4))


for i in range(40):
    n = cards[i % len(cards)]
    card = n if i < 20 else grouped(n, " " if i % 2 else "-")
    shapes = [
        f"Card number: {card}",
        f"User: my card {card} was declined, exp 12/29",
        json.dumps({"pan": card, "exp_month": 12, "exp_year": 2029}),
        f"2026-03-04T10:22:01Z WARN charge failed card={card} code=do_not_honor",
        f"Pay with {card} for the conference ticket.",
        f"cc: {card}",
        f"Use test card {card} in the sandbox.",
        f"Card on file {card}, billing ZIP 94103.",
    ]
    pos("credit_card", shapes[i % len(shapes)])


def luhn_ok(n):
    total = 0
    for i, d in enumerate(reversed([int(c) for c in n])):
        total += d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
    return total % 10 == 0


def luhn_bad(n):
    while luhn_ok(n):
        n = n[:-1] + str((int(n[-1]) + 1) % 10)
    return n


for n in cards[:12]:
    neg("credit_card", f"Card number: {grouped(luhn_bad(n[:-1] + str((int(n[-1]) + 3) % 10)), ' ')}")
cc_neg = [
    "Order 202603041022 shipped.",
    "Your confirmation code is 1234 5678 9012.",
    "Account 0001 2345 6789 0123 4567 8901 2345",
    "Card ending in 4242 was charged $12.00.",
    "**** **** **** 1111",
    "4111 XXXX XXXX 1111",
    "imei: 49-015420-323751-8",
]
for text in cc_neg:
    neg("credit_card", text)
for _ in range(7):
    neg("credit_card", f"ts={R.randint(1_700_000_000_000, 1_800_000_000_000)} event=page_view")
for _ in range(7):
    neg("credit_card", f"order_id={R.randint(10**15, 10**16 - 1)} status=paid")
for _ in range(7):
    t = "9400" + "".join(str(R.randint(0, 9)) for _ in range(18))
    neg("credit_card", f"USPS tracking {' '.join(t[i:i + 4] for i in range(0, 22, 4))}")

# --------------------------------------------------------------------------------------------------------------
# iban (synthetic accounts with correct ISO 13616 check digits, and two widely published examples)
# --------------------------------------------------------------------------------------------------------------
IBAN_FMT = {"GB": "4a14n", "DE": "18n", "FR": "10n11c2n", "NL": "4a10n", "IL": "19n", "ES": "20n", "IT": "1a10n12c",
            "CH": "5n12c", "BE": "12n", "AT": "16n", "SE": "20n", "PL": "24n", "IE": "4a14n", "PT": "21n"}


def bban(fmt):
    out, num = "", ""
    for ch in fmt:
        if ch.isdigit():
            num += ch
            continue
        alphabet = {"n": string.digits, "a": UP, "c": UPNUM}[ch]
        out += rnd(alphabet, int(num))
        num = ""
    return out


def iban_check(country, b):
    s = b + country + "00"
    rest = int("".join(str(int(c, 36)) for c in s)) % 97
    return f"{country}{98 - rest:02d}{b}"


def iban_mod(s):
    s = s.replace(" ", "")
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97


ibans = ["GB82WEST12345698765432", "DE89370400440532013000"]
countries = list(IBAN_FMT)
while len(ibans) < 40:
    c = countries[len(ibans) % len(countries)]
    ibans.append(iban_check(c, bban(IBAN_FMT[c])))
for i, iban in enumerate(ibans):
    assert iban_mod(iban) == 1
    shown = " ".join(iban[j:j + 4] for j in range(0, len(iban), 4)) if i % 2 else iban
    shapes = [
        f"IBAN: {shown}",
        f"Please wire the deposit to {shown}.",
        json.dumps({"iban": shown, "currency": "EUR"}),
        f"User: can you check {shown} is right before I pay?",
        f"Bank details: IBAN {shown} BIC COBADEFFXXX",
        f"payee_iban={shown}",
        f"Refund to account {shown}, reference INV-2026-0412.",
        f"Kontonummer (IBAN) {shown}",
    ]
    pos("iban", shapes[i % len(shapes)])
for iban in ibans[:2]:
    pos("iban", f"iban: {iban.lower()}")


def iban_broken(iban):
    digits = [j for j, c in enumerate(iban) if c.isdigit() and j >= 4]
    j = R.choice(digits)
    bad = iban[:j] + str((int(iban[j]) + R.randint(1, 9)) % 10) + iban[j + 1:]
    return bad if iban_mod(bad) != 1 else iban_broken(iban)


for iban in ibans[:16]:
    neg("iban", f"IBAN: {iban_broken(iban)}")
iban_neg = [
    "SWIFT/BIC COBADEFFXXX",
    "ISIN US0378331005",
    "VIN 1HGCM82633A004352",
    "GB00 0000 0000 0000 0000 00",
    "IBAN: XX00 XXXX XXXX XXXX XXXX XX",
    "Flight LH12 departs at 10:22 from gate B44",
    "Ref AB12CDEFGHIJKLMNOPQRST",
    "Use the IBAN field for European accounts.",
]
for text in iban_neg:
    neg("iban", text)
for _ in range(16):
    neg("iban", f"tracking {rnd(UP, 2)}{R.randint(10, 99)}{rnd(UPNUM, R.randint(11, 20))}")

# --------------------------------------------------------------------------------------------------------------
# israeli_id (random digits with a correct check digit; not issued to anyone known to the authors)
# --------------------------------------------------------------------------------------------------------------
def il_sum(d8):
    s = 0
    for i, c in enumerate(d8):
        p = int(c) * (1 + i % 2)
        s += p // 10 + p % 10
    return s


def il_id():
    d8 = "".join(str(R.randint(0, 9)) for _ in range(8))
    return d8 + str((10 - il_sum(d8) % 10) % 10)


def il_ok(n):
    return il_sum(n) % 10 == 0 and il_sum(n) > 0


ids = [il_id() for _ in range(38)]
for i, n in enumerate(ids):
    shapes = [
        f"מספר תעודת זהות: {n}",
        f"ID number {n}",
        json.dumps({"tz": n, "city": "Haifa"}),
        f"User: the form rejects my teudat zehut {n}",
        f"ת.ז. {n}",
        f"2026-03-04T10:22:01Z INFO kyc check national_id={n} result=pass",
        f"name,id\nTal R.,{n}",
        f"Israeli ID: {n}",
    ]
    pos("israeli_id", shapes[i % len(shapes)])
for n in ids[:2]:
    pos("israeli_id", f"ID {n[:8]}-{n[8]}")  # check digit written apart, as some forms print it


def il_bad():
    n = il_id()
    return n[:8] + str((int(n[8]) + R.randint(1, 9)) % 10)


for _ in range(16):
    neg("israeli_id", f"ID number {il_bad()}")
for _ in range(14):
    neg("israeli_id", f"invoice {R.randint(10**8, 10**9 - 1)} paid")
il_neg = [
    "000000000",
    "ID number 12345678",
    "ID number 1234567890",
    "zip 6100101",
    "build 2026030410",
    "Ticket TLV-48213",
    "ID: (pending)",
    "ID: see the attached scan",
    "PID 48213 exited",
    "routing 021000021 is a placeholder",
]
for text in il_neg:
    neg("israeli_id", text)

# --------------------------------------------------------------------------------------------------------------
# us_ssn (random numbers in valid ranges, tied to no one; known SSN shapes the SSA never issues are negatives)
# --------------------------------------------------------------------------------------------------------------
def ssn():
    area = R.choice([R.randint(1, 665), R.randint(667, 899)])
    return f"{area:03d}-{R.randint(1, 99):02d}-{R.randint(1, 9999):04d}"


for i in range(37):
    s = ssn()
    shapes = [
        f"SSN: {s}",
        f"User: I typed my social {s} on the form, did it save?",
        json.dumps({"ssn": s, "dob_year": 1987}),
        f"Employee SSN {s}, W-2 attached.",
        f"2026-03-04T10:22:01Z WARN pii in prompt ssn={s}",
        f"Social Security Number: {s}",
        f"ssn,state\n{s},CA",
        f"Applicant's SSN is {s}.",
    ]
    pos("us_ssn", shapes[i % len(shapes)])
for _ in range(2):
    pos("us_ssn", f"SSN: {ssn().replace('-', '')}")
pos("us_ssn", f"SSN: {ssn().replace('-', ' ')}")
ssn_neg = [
    "SSN: 000-12-3456",
    "SSN: 666-12-3456",
    "SSN: 912-34-5678",
    "SSN: 123-00-4567",
    "SSN: 123-45-0000",
    "SSN: ***-**-1234",
    "SSN: XXX-XX-XXXX",
    "SSN: on file",
    "Format SSNs as NNN-NN-NNNN.",
    "Released 2026-03-04",
]
for text in ssn_neg:
    neg("us_ssn", text)
for _ in range(10):
    neg("us_ssn", f"ITIN {R.randint(900, 999)}-{R.choice([R.randint(50, 65), R.randint(70, 88)])}-{R.randint(1000, 9999)}")
for label in ["Part no.", "Case", "Lot", "Ticket", "Ref", "Model", "Batch", "Claim", "Policy", "Docket"]:
    neg("us_ssn", f"{label} {ssn()}")
for _ in range(10):
    neg("us_ssn", f"Build {R.randint(100, 999)}-{R.randint(10, 99)}-{R.randint(10000, 99999)}")

# --------------------------------------------------------------------------------------------------------------
# medical_record_number (only after a label, as the detector promises)
# --------------------------------------------------------------------------------------------------------------
def mrn():
    return R.choice([f"{R.randint(10**5, 10**8 - 1)}", f"MR-{R.randint(10**4, 10**7)}", f"A{R.randint(10**6, 10**7)}",
                     f"{R.randint(1000, 9999)}-{R.randint(1000, 9999)}"])


for i in range(38):
    m = mrn()
    shapes = [
        f"Patient MRN: {m}",
        f"MRN#{m} admitted to ward 4",
        f"Medical record number: {m}",
        json.dumps({"note": f"Discharge summary for MRN {m}", "ward": "4B"}),
        f"User: pull the labs for medical record no. {m} please",
        f"2026-03-04T10:22:01Z INFO chart opened MRN={m}",
        f"Medical record {m}, allergies: penicillin",
        f"mrn: {m}",
    ]
    pos("medical_record_number", shapes[i % len(shapes)])
for _ in range(2):
    pos("medical_record_number", f"PID|1||{R.randint(10**5, 10**8)}^^^HOSP^MR||ROE^JANE")
mrn_neg = [
    "MRN: N/A",
    "MRN: pending",
    "The MRN field is required.",
    "MRNs are eight digits at this hospital.",
    "Medical records request form",
    "medical record review scheduled",
    "Medical Record Systems vendor demo",
    "MRN: [redacted]",
    "Ask for the MRN, not the date of birth.",
    "MRN lookup failed: timeout",
    "MRN: UNKNOWN",
    "the record number is on the wristband",
]
for text in mrn_neg:
    neg("medical_record_number", text)
for _ in range(14):
    neg("medical_record_number", f"Room {R.randint(100, 999)}, bed {R.randint(1, 4)}, ward {R.randint(1, 9)}{R.choice('ABC')}")
for _ in range(14):
    neg("medical_record_number", f"Order {R.randint(10**5, 10**8)} for patient transport")

# --------------------------------------------------------------------------------------------------------------
# date_of_birth (only after a label, as the detector promises)
# --------------------------------------------------------------------------------------------------------------
def date_str():
    y, mo, d = R.randint(1940, 2010), R.randint(1, 12), R.randint(1, 28)
    return R.choice([f"{mo:02d}/{d:02d}/{y}", f"{d}.{mo}.{y}", f"{y}-{mo:02d}-{d:02d}", f"{mo}/{d}/{y % 100:02d}",
                     f"{d:02d}-{mo:02d}-{y}"])


for i in range(36):
    dt = date_str()
    shapes = [
        f"DOB: {dt}",
        f"Patient date of birth: {dt}",
        json.dumps({"name": "J. Roe", "dob": f"DOB {dt}"}),
        f"User: I was born on {dt}, am I eligible?",
        f"Date of birth {dt}",
        f"2026-03-04T10:22:01Z INFO intake DOB={dt}",
        f"dob: {dt}",
        f"Applicant, born on {dt}, lives in Haifa.",
    ]
    pos("date_of_birth", shapes[i % len(shapes)])
for text in ["D.O.B.: 04/12/1987", "DOB: April 12, 1987", "Birth date: 1987-04-12", "birthdate 12/04/1987"]:
    pos("date_of_birth", text)
dob_neg = [
    "DOB: unknown",
    "The date of birth field is required.",
    "born on a Tuesday, as the song goes",
    "Created: 2026-03-04",
    "Expiry date 04/27",
    "Due date: 2026-12-01",
    "The project was born on 2019-04-01 as a weekend hack.",
    "DOB: [redacted]",
    "date of birth (DD/MM/YYYY)",
    "Last login 03/04/2026 10:22",
    "Valid from 01.01.2026 to 31.12.2026",
    "Release 2026-03-04, next one 2026-04-01",
]
for text in dob_neg:
    neg("date_of_birth", text)
for _ in range(14):
    neg("date_of_birth", f"Appointment on {date_str()} at {R.randint(8, 17)}:00")
for _ in range(14):
    neg("date_of_birth", f"Invoice dated {date_str()}, due in 30 days")

# --------------------------------------------------------------------------------------------------------------
# mixed: several kinds in one realistic message
# --------------------------------------------------------------------------------------------------------------
for i in range(10):
    addr = f"{R.choice(first)}.{R.choice(last)}@example.com"
    phone = f"+44 7700 900{R.randint(0, 999):03d}"
    card = grouped(cards[i], " ")
    add("mixed", f"Ticket from {addr}: please call me back on {phone}, the card {card} was charged twice.",
        ["email_address", "phone_number", "credit_card"])
for i in range(10):
    key = R.choice(["AKIA", "ASIA"]) + rnd(UPNUM, 16)
    gh_token = f"ghp_{rnd(ALNUM, 36)}"
    add("mixed", f"CI env dump:\nAWS_ACCESS_KEY_ID={key}\nGITHUB_TOKEN={gh_token}\nNODE_ENV=production",
        ["aws_access_key", "github_token"])

HEADER = [
    "# gantry-detectors-v1: a labelled corpus for Gantry's built-in secrets and pii detectors.",
    "# Made by scripts/make_detector_corpus.py (seeded, so it is reproducible). Each line is one JSON object:",
    "# target is the kind the line was written to test (or mixed), text is the text scanned, expect lists every",
    "# kind a careful reader would report in it, once per value. An empty expect is a hard negative.",
    "# Every value is synthetic or a published example value: AWS's documented example key, card networks' test",
    "# numbers, RFC 2606 mail domains, fictional phone ranges, random numbers with valid or broken checksums.",
    "# No real secret and no real person's data. License: Apache-2.0, as the rest of the repository.",
    "# Measured by crates/gantry-core/tests/detector_corpus.rs; published in docs/src/content/docs/governance/guardrails.mdx.",
]
OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w", encoding="utf-8") as fh:
    fh.write("\n".join(HEADER) + "\n")
    for i, row in enumerate(rows, 1):
        fh.write(json.dumps({"id": i, **row}, ensure_ascii=False) + "\n")
print(f"wrote {len(rows)} lines to {OUT}")

# ==============================================================================================================
# gantry-detectors-v2: v1, with OpenAI project and Anthropic keys given their own kinds, and the cloud and service
# keys v2 added. v1 above is written unchanged (same seed, same order); v2 draws from a seed of its own.
# ==============================================================================================================
import copy

OUT2 = OUT.with_name("gantry-detectors-v2.jsonl")
R2 = random.Random(20261114)


def rnd2(alphabet, n):
    return "".join(R2.choice(alphabet) for _ in range(n))


def relabel(row):
    row = copy.deepcopy(row)
    text = row["text"]
    if row["target"] == "api_key" and row["expect"]:
        if "sk-proj-" in text:
            row["target"], row["expect"] = "openai_project_key", ["openai_project_key"]
        elif "sk-ant-api" in text:
            row["target"], row["expect"] = "anthropic_key", ["anthropic_key"]
    return row


rows2 = [relabel(r) for r in rows]


def add2(target, text, expect):
    rows2.append({"target": target, "text": text, "expect": sorted(expect)})


def pos2(kind, value, label, key, i, extra=()):
    shapes = contexts(label, value, key)
    add2(kind, shapes[i % len(shapes)], [kind, *extra])


def neg2(kind, texts):
    for text in texts:
        add2(kind, text, [])


LOWER = string.ascii_lowercase
B64STD = string.ascii_letters + string.digits + "+/"

# gcp_service_account_key: the key file names its key by private_key_id; with the PEM in it, that is a private_key too.
for i in range(40):
    kid = rnd2(HEX, 40)
    proj = f"acme-{rnd2(LOWER, 6)}"
    if i % 2 == 0:
        block = f"-----BEGIN PRIVATE KEY-----\n{''.join(R2.choice(B64STD) for _ in range(64))}\n-----END PRIVATE KEY-----\n"
        doc = {"type": "service_account", "project_id": proj, "private_key_id": kid, "private_key": block,
               "client_email": f"ci@{proj}.iam.gserviceaccount.com"}
        extra = ["private_key"]
    else:
        doc = {"type": "service_account", "project_id": proj, "private_key_id": kid,
               "client_email": f"ci@{proj}.iam.gserviceaccount.com"}
        extra = []
    text = json.dumps(doc, indent=2 if i % 4 < 2 else None)
    if i % 3 == 0:
        text = f"User: gcloud says invalid_grant with this key file:\n{text}"
    # client_email is an address, so a careful reader reports it too.
    add2("gcp_service_account_key", text, ["gcp_service_account_key", "email_address", *extra])
neg2("gcp_service_account_key", [
    json.dumps({"type": "service_account", "project_id": "acme-prod", "private_key_id": "<KEY_ID>"}),
    json.dumps({"type": "service_account", "private_key_id": rnd2(HEX, 39)}),
    json.dumps({"type": "service_account", "private_key_id": rnd2(HEX, 40).upper()}),
    '"private_key_id": "${PRIVATE_KEY_ID}"',
    "Set private_key_id to the ID shown in the console.",
    json.dumps({"type": "authorized_user", "client_id": f"{R2.randint(10**11, 10**12)}.apps.googleusercontent.com"}),
    json.dumps({"key_id": rnd2(HEX, 40), "type": "service_account"}),
])
add2("gcp_service_account_key", "gcloud iam service-accounts keys list --iam-account ci@acme.iam.gserviceaccount.com",
     ["email_address"])
for _ in range(32):
    neg2("gcp_service_account_key", [
        f"commit {rnd2(HEX, 40)} Author: ci-bot"
        if R2.random() < 0.5 else
        json.dumps({"sha": rnd2(HEX, 40), "type": "commit", "private": False})
    ])

# gcp_api_key
for i in range(40):
    key = "AIza" + rnd2(ALNUM + "-_", 35)
    pos2("gcp_api_key", key, "Google API key", "google_api_key", i)
neg2("gcp_api_key", [
    "AIza...",
    "key=AIzaYOUR_API_KEY",
    "AIza" + rnd2(ALNUM, 20),
    "Google API keys start with AIza and are 39 characters long.",
    "maps.googleapis.com/maps/api/js?key=YOUR_KEY",
    "GOOGLE_API_KEY=${GOOGLE_API_KEY}",
])
for _ in range(34):
    neg2("gcp_api_key", [f"session=AIz{rnd2(ALNUM, 36)} " if R2.random() < 0.5 else f"id=GAIza{rnd2(ALNUM, 30)}"])

# azure_connection_string
for i in range(40):
    acct = f"acme{rnd2(LOWER + string.digits, 8)}"
    if i % 2 == 0:
        value = f"DefaultEndpointsProtocol=https;AccountName={acct};AccountKey={rnd2(B64STD, 86)}==;EndpointSuffix=core.windows.net"
    else:
        value = f"Endpoint=sb://{acct}.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey={rnd2(B64STD, 43)}="
    pos2("azure_connection_string", value, "Azure connection string", "azure_storage_connection_string", i)
neg2("azure_connection_string", [
    "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=<your-account-key>;EndpointSuffix=core.windows.net",
    "UseDevelopmentStorage=true",
    "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=${SB_KEY}",
    "AccountKey=",
    "Find the AccountKey under Access keys in the portal.",
    "BlobEndpoint=https://acme.blob.core.windows.net/;SharedAccessSignature=sv=2022-11-02&ss=b",
    "Server=tcp:acme.database.windows.net,1433;Initial Catalog=app;Authentication=Active Directory Default;",
])
for _ in range(33):
    neg2("azure_connection_string", [f"AccountName=acme{rnd2(LOWER, 6)};EndpointSuffix=core.windows.net;Key={rnd2(B64STD, 12)}"])

# stripe_key: secret and restricted keys; publishable keys are public by design.
for i in range(40):
    prefix = R2.choice(["sk_live_", "sk_test_", "rk_live_", "rk_test_"])
    key = prefix + rnd2(ALNUM, R2.choice([24, 32, 99]))
    pos2("stripe_key", key, "Stripe key", "stripe_secret_key", i)
neg2("stripe_key", [
    "pk_live_" + rnd2(ALNUM, 24),
    "pk_test_" + rnd2(ALNUM, 24),
    "sk_live_...",
    "sk_test_" + rnd2(ALNUM, 10),
    "STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}",
    "Stripe secret keys start with sk_live_ in live mode.",
    "whsec_" + rnd2(ALNUM, 32) + " is the webhook signing secret name in the docs",
    "desk_live_chat_widget_enabled",
])
for _ in range(32):
    neg2("stripe_key", [f"cus_{rnd2(ALNUM, 14)} pi_{rnd2(ALNUM, 24)} ch_{rnd2(ALNUM, 24)}"])

# twilio_api_key: API key SIDs; account SIDs are identifiers.
for i in range(40):
    pos2("twilio_api_key", "SK" + rnd2(HEX, 32), "Twilio API key", "twilio_api_key", i)
neg2("twilio_api_key", [
    "AC" + rnd2(HEX, 32),
    "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "SK" + rnd2(HEX, 31),
    "SK" + rnd2(HEX, 32).upper(),
    "TWILIO_ACCOUNT_SID=AC" + rnd2(HEX, 32),
    "MG" + rnd2(HEX, 32),
])
for _ in range(34):
    neg2("twilio_api_key", [f"{R2.choice(['AC', 'PN', 'MG', 'CA', 'SM'])}{rnd2(HEX, 32)} status=delivered"])

# sendgrid_key
for i in range(40):
    pos2("sendgrid_key", f"SG.{rnd2(ALNUM + '-_', 22)}.{rnd2(ALNUM + '-_', 43)}", "SendGrid API key", "sendgrid_api_key", i)
neg2("sendgrid_key", [
    "SG.xxxxx.yyyyy",
    "SENDGRID_API_KEY=SG.your-key-here",
    f"SG.{rnd2(ALNUM, 22)}.{rnd2(ALNUM, 20)}",
    "Keys look like SG.<22 characters>.<43 characters>.",
    "Singapore is SG.",
])
for _ in range(35):
    neg2("sendgrid_key", [f"version SG.{R2.randint(1, 9)}.{R2.randint(0, 99)} build {rnd2(HEX, 12)}"])

# openai_project_key: project, service account and admin keys (v1 rows with sk-proj- were relabelled above).
for i in range(30):
    prefix = R2.choice(["sk-proj-", "sk-svcacct-", "sk-admin-"])
    pos2("openai_project_key", prefix + rnd2(ALNUM + "-_", R2.choice([48, 74, 156])), "OpenAI key", "openai_api_key", i)
neg2("openai_project_key", [
    "sk-proj-...",
    "sk-proj-YOUR_KEY",
    "OPENAI_API_KEY=sk-proj-${KEY}",
    "Project keys start with sk-proj- and service accounts with sk-svcacct-.",
    "https://platform.openai.com/settings/proj_" + rnd2(ALNUM, 24) + "/api-keys",
    "sk-admin-",
])
for _ in range(34):
    neg2("openai_project_key", [f"proj_{rnd2(ALNUM, 24)} org-{rnd2(ALNUM, 24)} user-{rnd2(ALNUM, 24)}"])

# anthropic_key
for i in range(30):
    prefix = R2.choice(["sk-ant-api03-", "sk-ant-admin01-"])
    pos2("anthropic_key", prefix + rnd2(ALNUM + "-_", 93) + "AA", "Anthropic key", "anthropic_api_key", i)
neg2("anthropic_key", [
    "sk-ant-...",
    "sk-ant-api03-YOUR-KEY",
    "ANTHROPIC_API_KEY=sk-ant-${KEY}",
    "Anthropic keys start with sk-ant-api03-.",
    "sk-ant-admin01-",
    "x-api-key: $ANTHROPIC_API_KEY",
])
for _ in range(34):
    neg2("anthropic_key", [f"msg_{rnd2(ALNUM, 24)} req_{rnd2(ALNUM, 24)} toolu_{rnd2(ALNUM, 24)}"])

# api_key: more generic sk- keys, so the kind keeps 40 positives once project and Anthropic keys have their own.
for i in range(20):
    key = R2.choice([f"sk-{rnd2(ALNUM, 48)}", f"sk-{rnd2(HEX, 32)}", f"sk-or-v1-{rnd2(HEX, 64)}"])
    pos2("api_key", key, "API key", "api_key", i)

# database_url: a URL with a password; placeholders and password-less URLs are not secrets.
schemes = ["postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "redis", "rediss", "amqp", "amqps"]
for i in range(40):
    scheme = schemes[i % len(schemes)]
    user = R2.choice(["app", "svc_orders", "admin", "root", "reporting", ""])
    pw = rnd2(ALNUM + "-._~", R2.randint(10, 32))
    host = R2.choice(["db.internal", "10.0.3.12", f"{rnd2(LOWER, 8)}.rds.amazonaws.com", "cluster0.example.net"])
    port = {"postgres": 5432, "postgresql": 5432, "mysql": 3306, "mariadb": 3306, "redis": 6379, "rediss": 6380,
            "amqp": 5672, "amqps": 5671}.get(scheme)
    url = f"{scheme}://{user}:{pw}@{host}" + (f":{port}" if port else "") + "/app"
    pos2("database_url", url, "database URL", "database_url", i)
neg2("database_url", [
    "postgres://app@db.internal:5432/app",
    "postgres://db.internal/app",
    "postgres://app:${DB_PASSWORD}@db.internal/app",
    "mysql://root:password@localhost/test",
    "postgresql://user:<password>@host:5432/db",
    "mongodb+srv://svc:****@cluster0.example.net/prod",
    "redis://:${REDIS_PASSWORD}@cache:6379/0",
    "DATABASE_URL=postgres://$PGUSER:$PGPASSWORD@$PGHOST/app",
    "amqp://guest:xxx@localhost:5672/",
    "jdbc:postgresql://db.internal:5432/app?user=app",
    "Use the form postgres://user:pass@host/db.",
    "https://admin:changeme@grafana.example.com",
])
for _ in range(28):
    neg2("database_url", [f"{R2.choice(schemes)}://{R2.choice(['db.internal', 'cache', 'mq'])}:{R2.randint(1000, 9999)}/{rnd2(LOWER, 5)}"])

HEADER2 = [h.replace("gantry-detectors-v1", "gantry-detectors-v2") for h in HEADER]
HEADER2.insert(1, "# v2 is v1 with sk-proj- and sk-ant- keys labelled openai_project_key and anthropic_key, plus the cloud and")
HEADER2.insert(2, "# service key kinds v2 added (GCP, Azure, Stripe, Twilio, SendGrid, database URLs). Every key is random.")
with OUT2.open("w", encoding="utf-8") as fh:
    fh.write("\n".join(HEADER2) + "\n")
    for i, row in enumerate(rows2, 1):
        fh.write(json.dumps({"id": i, **row}, ensure_ascii=False) + "\n")
print(f"wrote {len(rows2)} lines to {OUT2}")
