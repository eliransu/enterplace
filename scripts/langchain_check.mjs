// LangChain.js against a local Gantry: run by scripts/langchain_check.py --js, which sets GANTRY_URL and GANTRY_KEY.
import assert from "node:assert/strict";
import { ChatOpenAI } from "@langchain/openai";
import { ChatAnthropic } from "@langchain/anthropic";
import { tool } from "@langchain/core/tools";
import { z } from "zod";

const base = process.env.GANTRY_URL;
const key = process.env.GANTRY_KEY;

const getWeather = tool(async () => "sunny", {
  name: "get_weather",
  description: "The weather in a city.",
  schema: z.object({ city: z.string() }),
});
const runShell = tool(async () => "", {
  name: "run_shell",
  description: "Run a shell command.",
  schema: z.object({ command: z.string() }),
});

const gpt = new ChatOpenAI({ model: "gpt-4o-mini", apiKey: key, configuration: { baseURL: `${base}/v1` }, maxRetries: 0 });
assert.equal((await gpt.invoke("Say hello.")).content, "hello");
let streamed = "";
for await (const chunk of await gpt.stream("Say hello.")) streamed += chunk.content;
assert.equal(streamed, "hello");
assert.equal((await gpt.bindTools([getWeather]).invoke("Weather in Haifa?")).tool_calls[0].name, "get_weather");

const claude = new ChatAnthropic({ model: "claude-sonnet-4-6", apiKey: key, anthropicApiUrl: base, maxTokens: 64, maxRetries: 0 });
assert.equal((await claude.invoke("Say hello.")).content, "hello");
assert.equal((await claude.bindTools([getWeather]).invoke("Weather in Haifa?")).tool_calls[0].name, "get_weather");

for (const [model, code] of [
  [new ChatOpenAI({ model: "gpt-4o", apiKey: key, configuration: { baseURL: `${base}/v1` }, maxRetries: 0 }), "model_not_allowed"],
  [gpt.bindTools([runShell]), "tool_not_allowed"],
  [claude.bindTools([runShell]), "tool_not_allowed"],
]) {
  await assert.rejects(model.invoke("hi"), (e) => String(e?.message ?? e).includes(code) || e?.code === code);
}
console.log("ok    LangChain JS: ChatOpenAI and ChatAnthropic, plain, streamed, tool calls, three refusals");
