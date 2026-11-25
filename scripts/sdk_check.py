"""Agent frameworks against a local Enterplace: the check behind the framework pages under
docs/src/content/docs/integrations (pydantic-ai, litellm-sdk, openai-agents-sdk, claude-agent-sdk, llamaindex, autogen, vercel-ai-sdk).

Usage:
  uv run --with 'pydantic-ai-slim[openai,anthropic]' --with litellm --with openai-agents \
    --with llama-index-llms-openai-like \
    --with autogen-agentchat --with 'autogen-ext[openai]' --with claude-agent-sdk \
    python3 scripts/sdk_check.py [enterplace binary] [--js]

Uses the mock provider, policy and gateway of scripts/langchain_check.py (plus a Responses answer), and drives each
framework through Enterplace: one call per API it speaks, and a model the rule does not allow, which must surface
Enterplace's `model_not_allowed`. A framework that is not installed is reported as skipped, not passed. With --js it
also runs scripts/sdk_check.mjs (the Vercel AI SDK) with Node, after installing it in a temporary folder.
No provider key is needed. It needs network access to install the frameworks, so it is not part of scripts/ci.sh.
claude-agent-sdk brings a Claude Code binary of its own; the others are plain Python packages.
"""
import asyncio, importlib.metadata, json, os, pathlib, subprocess, sys, tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import langchain_check as harness

KEY = harness.KEY


class Provider(harness.Provider):
    def do_POST(self):
        if self.path.split("?")[0].endswith("/messages"):
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))) or b"{}")
            if body.get("stream") is True:  # Pydantic AI streams its Anthropic requests
                return self.send("text/event-stream", "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in message_events(body["model"])))
            return self.send("application/json", json.dumps({
                "id": "m", "type": "message", "role": "assistant", "model": body["model"], "content": [{"type": "text", "text": "hello"}],
                "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 3, "output_tokens": 1}}))
        if not self.path.endswith("/responses"):
            return super().do_POST()
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))) or b"{}")
        item = {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": "hello", "annotations": []}]}
        self.send("application/json", json.dumps({
            "id": "resp_1", "object": "response", "created_at": 1, "model": body["model"], "status": "completed", "output": [item],
            "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
            "usage": {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4,
                      "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}))


def message_events(model):
    """Anthropic's streamed events for the answer "hello"."""
    start = {"id": "m", "type": "message", "role": "assistant", "model": model, "content": [], "stop_reason": None, "stop_sequence": None,
             "usage": {"input_tokens": 3, "output_tokens": 0}}
    return [{"type": "message_start", "message": start},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello"}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 1}},
            {"type": "message_stop"}]


def refused(call):
    """The call must fail with Enterplace's model_not_allowed somewhere in the framework's error."""
    try:
        result = call()
        if asyncio.iscoroutine(result):
            asyncio.run(result)
    except Exception as e:  # each framework wraps the SDK's error in its own type
        chain, seen = [], e
        while seen and len(chain) < 6:
            chain.append(f"{seen!r} {getattr(seen, 'body', '')}")
            seen = seen.__cause__ or seen.__context__
        assert "model_not_allowed" in " ".join(chain), chain
        return
    raise AssertionError("expected model_not_allowed")


def pydantic_ai(base):
    from pydantic_ai import Agent
    from pydantic_ai.models.anthropic import AnthropicModel
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.anthropic import AnthropicProvider
    from pydantic_ai.providers.openai import OpenAIProvider

    enterplace = OpenAIProvider(base_url=f"{base}/v1", api_key=KEY)
    assert Agent(OpenAIChatModel("gpt-4o-mini", provider=enterplace)).run_sync("Say hello.").output == "hello"
    claude = AnthropicModel("claude-sonnet-4-6", provider=AnthropicProvider(base_url=base, api_key=KEY))
    assert Agent(claude).run_sync("Say hello.").output == "hello"
    refused(lambda: Agent(OpenAIChatModel("gpt-4o", provider=enterplace)).run_sync("hi"))
    return "pydantic-ai-slim", "chat completions, messages, one refusal"


def litellm_sdk(base):
    import litellm

    say = [{"role": "user", "content": "Say hello."}]
    answer = litellm.completion(model="openai/gpt-4o-mini", api_base=f"{base}/v1", api_key=KEY, messages=say)
    assert answer.choices[0].message.content == "hello"
    chunks = litellm.completion(model="openai/gpt-4o-mini", api_base=f"{base}/v1", api_key=KEY, messages=say, stream=True)
    assert "".join(c.choices[0].delta.content or "" for c in chunks) == "hello"
    answer = litellm.completion(model="anthropic/claude-sonnet-4-6", api_base=base, api_key=KEY, messages=say, max_tokens=64)
    assert answer.choices[0].message.content == "hello"
    refused(lambda: litellm.completion(model="openai/gpt-4o", api_base=f"{base}/v1", api_key=KEY, messages=say, num_retries=0))
    return "litellm", "chat completions plain and streamed, messages, one refusal"


def openai_agents(base):
    from agents import Agent, OpenAIChatCompletionsModel, OpenAIResponsesModel, Runner, set_tracing_disabled
    from openai import AsyncOpenAI

    set_tracing_disabled(True)
    client = AsyncOpenAI(base_url=f"{base}/v1", api_key=KEY, max_retries=0)
    for model in (OpenAIResponsesModel(model="gpt-4o-mini", openai_client=client), OpenAIChatCompletionsModel(model="gpt-4o-mini", openai_client=client)):
        agent = Agent(name="Greeter", instructions="Be brief.", model=model)
        assert asyncio.run(Runner.run(agent, "Say hello.")).final_output == "hello"
    blocked = Agent(name="Greeter", model=OpenAIChatCompletionsModel(model="gpt-4o", openai_client=client))
    refused(lambda: Runner.run(blocked, "hi"))
    return "openai-agents", "Responses, chat completions, one refusal"


def llamaindex(base):
    from llama_index.llms.openai_like import OpenAILike

    gpt = OpenAILike(model="gpt-4o-mini", api_base=f"{base}/v1", api_key=KEY, is_chat_model=True)
    assert gpt.complete("Say hello.").text == "hello"
    assert "".join(c.delta or "" for c in gpt.stream_complete("Say hello.")) == "hello"
    refused(lambda: OpenAILike(model="gpt-4o", api_base=f"{base}/v1", api_key=KEY, is_chat_model=True, max_retries=0).complete("hi"))
    return "llama-index-llms-openai-like", "chat completions plain and streamed, one refusal"


def autogen(base):
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    client = OpenAIChatCompletionClient(model="gpt-4o-mini", base_url=f"{base}/v1", api_key=KEY)
    result = asyncio.run(AssistantAgent("greeter", model_client=client).run(task="Say hello."))
    assert result.messages[-1].content == "hello", result
    blocked = OpenAIChatCompletionClient(model="gpt-4o", base_url=f"{base}/v1", api_key=KEY, max_retries=0)
    refused(lambda: AssistantAgent("greeter", model_client=blocked).run(task="hi"))
    return "autogen-agentchat", "chat completions, one refusal"


def claude_agent_sdk(base):
    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    def options(**more):
        # A config folder of its own, so the bundled Claude Code reads none of this machine's sign-ins or settings.
        env = {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_API_KEY": KEY, "ANTHROPIC_DEFAULT_HAIKU_MODEL": "claude-sonnet-4-6",
               "CLAUDE_CONFIG_DIR": tempfile.mkdtemp(), "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}
        return ClaudeAgentOptions(model="claude-sonnet-4-6", cwd=tempfile.mkdtemp(), env=env, **more)

    async def ask(opts):
        text = ""
        async for message in query(prompt="Say hello.", options=opts):
            if isinstance(message, AssistantMessage):
                text += "".join(block.text for block in message.content if isinstance(block, TextBlock))
        return text

    assert asyncio.run(ask(options(tools=[]))) == "hello"
    try:  # With its built-in tools declared, the rule's tools: list refuses the request.
        asyncio.run(ask(options()))
        raise AssertionError("expected tool_not_allowed")
    except Exception as e:
        assert "tool_not_allowed" in str(e), e
    return "claude-agent-sdk", "messages, one refusal (tool_not_allowed for its built-in tools)"


def js_checks(base):
    work = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-sdk-js-"))
    subprocess.run(["npm", "install", "--silent", "--no-audit", "--no-fund", "ai", "@ai-sdk/openai", "@ai-sdk/anthropic"], cwd=work, check=True)
    (work / "check.mjs").write_text((pathlib.Path(__file__).resolve().parent / "sdk_check.mjs").read_text())
    subprocess.run(["node", "check.mjs"], cwd=work, check=True, env={**os.environ, "ENTERPLACE_URL": base, "ENTERPLACE_KEY": KEY})


def checks(base):
    failed = False
    for check in (pydantic_ai, litellm_sdk, openai_agents, llamaindex, autogen, claude_agent_sdk):
        try:
            package, what = check(base)
            print(f"ok    {package} {importlib.metadata.version(package)}: {what}")
        except ImportError as e:
            print(f"skip  {check.__name__}: not installed ({e.name})")
        except Exception as e:
            failed = True
            print(f"FAIL  {check.__name__}: {e!r}")
    if "--js" in sys.argv:
        js_checks(base)
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    harness.main(checks, Provider)
