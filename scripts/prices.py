#!/usr/bin/env python3
"""Turns LiteLLM's model price map into the price table built into Gantry.

Usage: scripts/prices.py <model_prices_and_context_window.json> <commit sha> <date YYYY-MM-DD>

Download the JSON data file alone, never LiteLLM's code (AGENTS.md rule 3):
  curl -sSfLo /some/empty/dir/prices.json \
    https://raw.githubusercontent.com/BerriAI/litellm/<commit>/model_prices_and_context_window.json

Writes crates/gantry-core/data/litellm-prices.tsv. The map is MIT licensed; the license and attribution are in
crates/gantry-core/data/LICENSE-litellm-prices.
"""

import json
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "crates/gantry-core/data/litellm-prices.tsv"
URL = "https://raw.githubusercontent.com/BerriAI/litellm/{}/model_prices_and_context_window.json"
# A name with a provider prefix ("vertex_ai/gemini-2.5-pro") is also listed under its bare name, which is what a
# caller sends to Gantry, unless the bare name has an entry of its own. When several prefixes share a bare name,
# the first provider here wins: the vendor's own price over a reseller's.
FIRST = ["openai", "anthropic", "gemini", "vertex_ai", "mistral", "groq", "deepseek", "xai", "bedrock"]
LONG = re.compile(r"^input_cost_per_token_above_(\d+)k_tokens$")
COLUMNS = ["model", "input", "output", "cache_read", "cache_write", "cache_write_1h", "per_image",
           "max_output", "max_context", "long_above", "long_input", "long_output", "long_cache_read",
           "long_cache_write", "input_audio", "output_audio", "cache_read_audio", "batch_input", "batch_output",
           "batch_cache_read"]


def per_mtok(value):
    """Dollars per token to dollars per million tokens, without float noise such as 2.4999999999999996."""
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        return ""
    return repr(float(f"{value * 1e6:.10g}"))


def whole(value):
    return str(value) if isinstance(value, int) and not isinstance(value, bool) and value > 0 else ""


def row(name, entry):
    image = entry.get("output_cost_per_image")
    priced = "input_cost_per_token" in entry and "output_cost_per_token" in entry
    if not priced and not isinstance(image, (int, float)):
        return None
    cells = [
        name,
        per_mtok(entry.get("input_cost_per_token", 0)),
        per_mtok(entry.get("output_cost_per_token", 0)),
        per_mtok(entry.get("cache_read_input_token_cost")),
        per_mtok(entry.get("cache_creation_input_token_cost")),
        per_mtok(entry.get("cache_creation_input_token_cost_above_1hr")),
        repr(float(image)) if isinstance(image, (int, float)) and image >= 0 else "",
        whole(entry.get("max_output_tokens")),
        whole(entry.get("max_input_tokens")),
    ]
    # The lowest long context tier: a prompt above it pays these prices for all of its tokens.
    tiers = sorted(int(m.group(1)) for k in entry if (m := LONG.match(k)))
    if tiers and f"output_cost_per_token_above_{tiers[0]}k_tokens" in entry:
        k = tiers[0]
        cells += [
            str(k * 1000),
            per_mtok(entry[f"input_cost_per_token_above_{k}k_tokens"]),
            per_mtok(entry[f"output_cost_per_token_above_{k}k_tokens"]),
            per_mtok(entry.get(f"cache_read_input_token_cost_above_{k}k_tokens")),
            per_mtok(entry.get(f"cache_creation_input_token_cost_above_{k}k_tokens")),
        ]
    else:
        cells += [""] * 5
    # Audio tokens (realtime and audio models) and the batch API's own prices, where the map gives them.
    cells += [
        per_mtok(entry.get("input_cost_per_audio_token")),
        per_mtok(entry.get("output_cost_per_audio_token")),
        per_mtok(entry.get("cache_read_input_audio_token_cost")),
        per_mtok(entry.get("input_cost_per_token_batches")),
        per_mtok(entry.get("output_cost_per_token_batches")),
        per_mtok(entry.get("cache_read_input_token_cost_batches")),
    ]
    if "" in cells[1:3] or any("\t" in c or "\n" in c for c in cells):
        return None
    return cells


def main():
    if len(sys.argv) != 4 or not re.fullmatch(r"[0-9a-f]{40}", sys.argv[2]) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}", sys.argv[3]
    ):
        sys.exit(__doc__)
    data = json.loads(Path(sys.argv[1]).read_text())
    rows = {}
    for name, entry in data.items():
        if name == "sample_spec" or not isinstance(entry, dict):
            continue
        cells = row(name, entry)
        if cells:
            rows[name] = cells
    bare = {}
    for name, cells in rows.items():
        if "/" not in name:
            continue
        prefix, tail = name.split("/", 1)
        tail = tail.rsplit("/", 1)[-1]
        rank = FIRST.index(prefix) if prefix in FIRST else len(FIRST)
        if tail not in rows and (tail not in bare or rank < bare[tail][0]):
            bare[tail] = (rank, [tail] + cells[1:])
    for tail, (_, cells) in bare.items():
        rows[tail] = cells
    lines = [
        f"# source\t{URL.format(sys.argv[2])}",
        f"# date\t{sys.argv[3]}",
        "# license\tMIT, Copyright (c) 2023 Berri AI. See LICENSE-litellm-prices beside this file.",
        "# units\tUS dollars per million tokens; per_image in dollars per image; max_output, max_context in tokens",
        "\t".join(COLUMNS),
    ]
    lines += ["\t".join(rows[name]) for name in sorted(rows)]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n")
    print(f"{OUT}: {len(rows)} models")


if __name__ == "__main__":
    main()
