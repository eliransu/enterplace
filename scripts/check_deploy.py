"""Checks the Helm chart in deploy/ without a cluster: YAML parses, the security settings are there, and the policy passes
`gantry check`.
Also checks the OpenTelemetry Collector recipe in the observability docs page against audit records a real Gantry writes
(it starts `gantry serve` on 127.0.0.1:20953 for a moment).

Usage: python3 scripts/check_deploy.py [path/to/gantry]
helm is not required: when it is on PATH, `helm lint` and `helm template` run too, and the rendered StatefulSet's pod is
checked in full. Without it the chart's templates are only checked for balanced blocks. The Terraform modules, the
Cloudflare template and the Compose guide are checked by .github/workflows/deploy-targets.yml.
YAML is parsed with Ruby's bundled Psych, because Python's standard library has no YAML parser. Never contacts a cluster.
"""
import json, pathlib, re, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHART = ROOT / "deploy" / "helm" / "gantry"
OBSERVABILITY = ROOT / "docs" / "src" / "content" / "docs" / "operations" / "observability.mdx"
GANTRY = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "debug" / "gantry"


def load_all(path: pathlib.Path) -> list:
    out = subprocess.run(["ruby", "-ryaml", "-rjson", "-e", "puts JSON.generate(YAML.load_stream(File.read(ARGV[0])))", str(path)], capture_output=True, text=True)
    if out.returncode:
        sys.exit(f"{path}: not valid YAML: {out.stderr.strip()}")
    return [d for d in json.loads(out.stdout) if d]


def check_pod(spec: dict, where: str) -> None:
    pod = spec["securityContext"]
    assert pod["runAsNonRoot"] and pod["runAsUser"] == 65532 and pod["fsGroup"] == 65532, where
    for c in spec["containers"] + spec.get("initContainers", []):
        sc = c["securityContext"]
        assert sc["readOnlyRootFilesystem"] and not sc["allowPrivilegeEscalation"] and sc["capabilities"]["drop"] == ["ALL"], where
        assert c["resources"]["requests"]["cpu"] and c["resources"]["requests"]["memory"], where
        if c in spec.get("initContainers", []):
            continue
        assert c["readinessProbe"]["httpGet"]["path"] == "/readyz" and c["livenessProbe"]["httpGet"]["path"] == "/healthz", where
        mounts = {m["mountPath"] for m in c["volumeMounts"]}
        assert "/var/lib/gantry" in mounts, f"{where}: the audit log needs its writable volume"


def gantry_check(policy: str, where: str) -> None:
    if not GANTRY.exists():
        print(f"skipped gantry check of {where}: {GANTRY} not built")
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "gantry.policy.yaml"
        path.write_text(policy)
        out = subprocess.run([str(GANTRY), "check", str(path)], capture_output=True, text=True)
        assert out.returncode == 0, f"{where}: gantry check failed:\n{out.stdout}{out.stderr}"


def check_otel() -> None:
    """The Collector recipe in the observability docs page parses, and its timestamp layout fits every record a real Gantry wrote."""
    text = OBSERVABILITY.read_text()
    block = re.search(r"### OpenTelemetry Collector.*?```yaml\n(.*?)```", text, re.S)
    assert block, "no Collector recipe in the observability docs page"
    with tempfile.TemporaryDirectory() as tmp:
        recipe = pathlib.Path(tmp) / "collector.yaml"
        recipe.write_text(block.group(1))
        config = load_all(recipe)[0]
    operator = config["receivers"]["filelog/gantry"]["operators"][0]
    assert operator["timestamp"]["parse_from"] == "attributes.time" and operator["parse_to"] == "attributes"
    assert config["receivers"]["filelog/gantry"]["include"] == ["/var/lib/gantry/gantry-audit.jsonl"]
    if not GANTRY.exists():
        print(f"skipped the audit record check: {GANTRY} not built")
        return
    # A real audit log: start Gantry, send one refused request, stop it.
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "p.yaml").write_text(load_all(CHART / "values.yaml")[0]["policy"].replace("/var/lib/gantry/", f"{d}/"))
        (d / "k.yaml").write_text("keys: []\n")
        server = subprocess.Popen([str(GANTRY), "serve", str(d / "p.yaml"), "--keys", str(d / "k.yaml"), "--listen", "127.0.0.1:20953"], env={"OPENAI_PROVIDER_KEY": "not-a-real-key"}, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            assert server.stdout and "listening" in server.stdout.readline()
            import urllib.request, urllib.error
            request = urllib.request.Request("http://127.0.0.1:20953/v1/chat/completions", data=b'{"model":"gpt-4o-mini","messages":[]}', headers={"Authorization": "Bearer nope", "Content-Type": "application/json"})
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as refused:
                assert refused.code == 401
        finally:
            server.terminate()
            server.wait(10)
        lines = (d / "gantry-audit.jsonl").read_text().splitlines()
    assert len(lines) >= 2, lines
    for line in lines:
        record = json.loads(line)
        assert isinstance(record, dict)
        # The Go layout 2006-01-02T15:04:05.000Z07:00 with a UTC "Z", as Gantry always writes it.
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", record["time"]), record["time"]
    print(f"Collector recipe parses; {len(lines)} audit records fit its timestamp layout")


def main() -> None:
    values = load_all(CHART / "values.yaml")[0]
    load_all(CHART / "Chart.yaml")
    policy = values["policy"]
    assert "/var/lib/gantry/" in policy, "the audit log must be on the writable volume"
    gantry_check(policy, str(CHART / "values.yaml"))
    for template in (CHART / "templates").glob("*.yaml"):
        text = template.read_text()
        opened = len(re.findall(r"\{\{-?\s*(if|with|range|define)\b", text))
        closed = len(re.findall(r"\{\{-?\s*end\s*-?\}\}", text))
        assert opened == closed, f"{template}: {opened} blocks opened, {closed} closed"

    if shutil.which("helm"):
        subprocess.run(["helm", "lint", "--strict", str(CHART)], check=True, capture_output=True)
        for extra in [[], *(["-f", str(f)] for f in sorted((CHART / "ci").glob("*.yaml")))]:
            subprocess.run(["helm", "lint", "--strict", str(CHART), *extra], check=True, capture_output=True)
        with tempfile.TemporaryDirectory() as tmp:
            rendered = pathlib.Path(tmp) / "chart.yaml"
            rendered.write_text(subprocess.run(["helm", "template", "gantry", str(CHART), "--set", "metrics.enabled=true,metrics.serviceMonitor.enabled=true,ingress.enabled=true"], check=True, capture_output=True, text=True).stdout)
            kinds = {d["kind"]: d for d in load_all(rendered)}
        statefulset = kinds["StatefulSet"]["spec"]
        assert statefulset["replicas"] == 1, "one replica without a store"
        check_pod(statefulset["template"]["spec"], "the rendered StatefulSet")
        assert kinds["ConfigMap"]["data"]["gantry.policy.yaml"] == policy, "the rendered policy is not values.yaml's"
        print("helm lint (with each ci/ values file) and helm template passed; the pod's security settings hold")
    else:
        print("helm is not installed: the chart's templates were checked for balanced blocks only, not rendered")
    check_otel()
    print("deploy/ checks passed")


if __name__ == "__main__":
    main()
