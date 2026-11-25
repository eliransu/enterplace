// The Vercel AI SDK against a local Enterplace. Run by scripts/sdk_check.py --js, which sets ENTERPLACE_URL and ENTERPLACE_KEY.
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import { generateText, streamText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";
import { createAnthropic } from "@ai-sdk/anthropic";

const base = process.env.ENTERPLACE_URL, apiKey = process.env.ENTERPLACE_KEY;
const openai = createOpenAI({ baseURL: `${base}/v1`, apiKey });
const anthropic = createAnthropic({ baseURL: `${base}/v1`, apiKey });

assert.equal((await generateText({ model: openai.chat("gpt-4o-mini"), prompt: "Say hello." })).text, "hello");
assert.equal((await generateText({ model: openai("gpt-4o-mini"), prompt: "Say hello." })).text, "hello");
let streamed = "";
for await (const part of streamText({ model: openai.chat("gpt-4o-mini"), prompt: "Say hello." }).textStream) streamed += part;
assert.equal(streamed, "hello");
assert.equal((await generateText({ model: anthropic("claude-sonnet-4-6"), prompt: "Say hello.", maxOutputTokens: 64 })).text, "hello");
try {
  await generateText({ model: openai.chat("gpt-4o"), prompt: "hi", maxRetries: 0 });
  assert.fail("expected model_not_allowed");
} catch (e) {
  assert.match(String(e.responseBody ?? e.message), /model_not_allowed/);
}
const version = createRequire(import.meta.url)("ai/package.json").version;
console.log(`ok    Vercel AI SDK ${version}: chat completions plain and streamed, Responses, messages, one refusal`);
