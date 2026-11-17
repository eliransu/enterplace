# Moving from LiteLLM

`enterplace import litellm` reads a LiteLLM proxy `config.yaml` and writes a Enterplace policy that passes `enterplace check`, with a list of everything it could not carry across. Keys cannot move: LiteLLM keeps only their hashes, as Enterplace does. An export of LiteLLM's virtual keys becomes team rules and the commands to reissue each key.

```bash
enterplace import litellm config.yaml --out enterplace.policy.yaml
enterplace import litellm config.yaml --keys-from keys.json --out enterplace.policy.yaml
```

It never replaces an existing file, runs `enterplace check` on what it wrote, and prints each item it could not map with what to do instead. Read the policy before serving it: it allows every imported model to anyone with a key (`principals: { any: true }`, as a LiteLLM proxy allows any valid key every model by default), after the team rules a key export adds.

## What maps to what

| LiteLLM | Enterplace |
|---|---|
| `model_list[].model_name` | The model name callers send. One deployment whose model has the same name is listed under its provider's `models`; several deployments, or one under another name, become an [alias](providers.html#aliases-and-load-balancing) with that name. |
| `litellm_params.model` `openai/`, bare `gpt-*` | `kind: openai`, `url: https://api.openai.com` |
| `anthropic/`, bare `claude-*` | `kind: anthropic` |
| `azure/<deployment>` with `api_base`, `api_version` | `kind: azure` with `deployments` and `api_version` |
| `bedrock/<model id>` with `aws_region_name` | `kind: bedrock` with `region` and `model_ids` (Enterplace signs with its own `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`) |
| `gemini/` | `kind: gemini` |
| `vertex_ai/gemini-*` with `vertex_project`, `vertex_location` | `kind: vertex` with the `/publishers/google` URL |
| `vertex_ai/claude-*` with `vertex_project`, `vertex_location` | `kind: vertex_anthropic` with the `/publishers/anthropic` URL, and an alias from the `model_name` to the Vertex model name (`claude-sonnet-4-5@20250929`) |
| `groq/`, `mistral/`, `together_ai/`, `fireworks_ai/`, `deepseek/`, `openrouter/`, `ollama/`, `ollama_chat/`, `lm_studio/`, `hosted_vllm/` | `kind: openai` with the vendor's base URL from [Providers](providers.html#base-urls-at-a-glance), or `api_base`; a local one gets `allow_private: true` and no key |
| `api_key: os.environ/NAME` | `key_env: NAME`. A key written in the config is not copied: the report names the variable to set. |
| `litellm_params.weight` | the deployment's `weight` |
| `model_info.input_cost_per_token`, `output_cost_per_token` | `prices:` in dollars per million tokens, under the name Enterplace sends. |
| A deployment named by its owner (`azure/gpt-4o-eastus`) | priced as the model it runs: `model_info.base_model` when set, else the LiteLLM model string, else the `model_name`, written under `prices:` for the deployment's name. So a team budget or a key `tpm` works on the imported alias. A deployment none of these prices is reported, with the `prices:` line to add. Check one with `enterplace prices <alias> --policy enterplace.policy.yaml`. |
| `router_settings.routing_strategy` `simple-shuffle`, `least-busy` | alias `balance: round_robin`, `least_busy`; other strategies are reported and use `round_robin` |
| `router_settings.cooldown_time` | alias `cooldown_seconds` (up to 3600) |
| `num_retries` (router or litellm settings) | each provider's `retries` (up to 5) |
| `context_window_fallbacks`, `content_policy_fallbacks` | the alias's `context_window_fallback`, `content_policy_fallback` (the first target; Enterplace follows one) |
| `fallbacks` | reported: Enterplace fails over between an alias's deployments, or from a provider to its `fallback` provider for the same model. Add the fallback as a deployment of the alias if it may also take a share of traffic. |
| `rpm`, `tpm` per deployment | reported: Enterplace limits people, teams and keys (`rate:` on a rule, `tpm:` on a key) |
| `general_settings.master_key` | reported: make an admin key with `enterplace key new <name> --team <team> --admin` |
| `general_settings.database_url`, `redis_*` | reported: not needed; keys are a file, records are the audit log, cooldowns are in memory on one node |
| `litellm_settings.drop_params` | reported: Enterplace never drops a parameter silently |
| `cache`, `cache_params` | reported: add `cache: { ttl_seconds: N }` to a rule |
| `success_callback`, `callbacks` | reported: every request is in the audit log, and `/metrics` serves Prometheus ([Metrics and log shipping](observability.html)) |
| anything else | reported as not mapped |

Not served by Enterplace, so reported and left out: Vertex AI models other than Gemini and Claude, and providers with no Enterplace kind and no OpenAI-compatible URL.

## Keys

`--keys-from` reads an export of LiteLLM virtual keys: a JSON list (or an object with the list under `keys` or `data`), or CSV with a header row. It reads `key_alias` (else `user_email`, `user_id`, `key_name`) as the person, `team_alias` (else `team_id`) as the team, `models`, `max_budget` with `budget_duration`, `expires`, `tpm_limit` and `rpm_limit`.

- Each team gets a rule `team-<team>` before `everyone`, allowing the models its keys list (`["*"]` when one of its keys lists none, which in LiteLLM means every model).
- Each key gets a line to reissue it: `enterplace key new maya --team payments --budget 20/month --expires 2027-01-01 --models gpt-4o,gpt-4o-mini --tpm 50000`, carrying its `models` (those this config serves) and `tpm_limit`. A key that has already expired is reported and gets no line. A CSV `models` column may be quoted with commas inside (`"gpt-4o,gpt-4o-mini"`). A `budget_duration` of `1d` or `24h` is a day; `30d`, `1mo` or `1m` a month; any other is reported. Developers can instead get their own key with [`enterplace login`](keys.html#developers-get-their-own-key-enterplace-login).
- `rpm_limit` has no per-key equivalent and is reported.

## Two regions of one model

Two deployments of `gpt-4o` at two OpenAI-compatible URLs become two providers and one alias `gpt-4o`. A model name belongs to one provider, so the second provider lists it as `gpt-4o@<provider>`; callers send `gpt-4o` and the alias sends the real name to whichever deployment it picks. For Azure and Bedrock the `@` name is a key of `deployments` or `model_ids`, so it also works when sent directly.

## Sources

The config format was read from LiteLLM's public docs on 2026-11-13: https://docs.litellm.ai/docs/proxy/configs, https://docs.litellm.ai/docs/proxy/reliability, https://docs.litellm.ai/docs/proxy/config_settings, https://docs.litellm.ai/docs/proxy/virtual_keys. No LiteLLM code was read. Tested against sample configs in those shapes (`crates/enterplace-core/src/litellm.rs` tests, and `import_litellm_writes_a_policy_that_checks_and_never_replaces_one` in `crates/enterplace-cli/tests/cli.rs`), not against a running LiteLLM.
