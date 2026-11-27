// "Copy for your agent" prompts built in the browser, for what only the browser holds: a key shown once is never
// sent back to the server, so its prompt cannot come from there. Same layout as the server's task_prompt.

const DOCS = "https://docs.enterplace.dev";

function taskPrompt(
  goal: string,
  values: [string, string][],
  todo: string[],
  verify: string,
  doc: string,
): string {
  const base = window.location.origin;
  const lines = [
    `Goal: ${goal}, for the Enterplace AI gateway at ${base}.`,
    "",
    "Values:",
    `- Enterplace URL: ${base}`,
    ...values.map(([name, value]) => `- ${name}: ${value}`),
    "",
    "Do this:",
    ...todo,
    "",
    `Verify: ${verify}`,
    "",
    // Same words as the server's REFUSED: the refusal carries the gateway's fix, which an admin applies.
    "If a call is refused, read the refusal's fix: tell me the exact gateway steps it names, word for word with the link, wait until I say they are done, then retry the same call. Do not change the app to work around it.",
    "",
    `Docs (Markdown, read it for anything not covered here): ${DOCS}${doc.replace(/\/$/, "")}.md`,
    "",
    "Do not print, log or commit any key or token other than the values above, and ask me before changing anything else.",
  ];
  return `${lines.join("\n")}\n`;
}

/// The prompt for a key just made: a service key wires an app or agent's code; a person token routes Claude Code on
/// the person's own login; a key points the person's coding tools at the gateway.
export function madePrompt(
  made: { key: string; name: string; team: string; lines?: string[] },
  service: boolean,
): string {
  const base = window.location.origin;
  const requests = `${base}/console/app/#/requests`;
  if (service) {
    return taskPrompt(
      `Connect the app or agent ${made.name} in this project to Enterplace`,
      [
        ["Service key", made.key],
        ["OpenAI-compatible base URL", `${base}/v1`],
        ["Anthropic base URL", base],
      ],
      [
        "1. Find where this project calls a model provider (OpenAI, Anthropic, or an SDK or framework on top of them).",
        "2. Put the service key in the project's secret store or a git-ignored .env file, never in code or in git. Use OPENAI_API_KEY or ANTHROPIC_API_KEY, whichever the client reads.",
        "3. Set the client's base URL to the one above for its provider (OPENAI_BASE_URL or ANTHROPIC_BASE_URL), through configuration, not hard-coded.",
        "4. Keep the model names as they are. Enterplace refuses a model its rule does not allow, and the refusal names the rule and the fix.",
        "5. Run the app, or its test that calls the model, once.",
      ],
      `The request shows at ${requests} under ${made.name}, team ${made.team}.`,
      "/integrations/connect-a-project/",
    );
  }
  if (made.key.startsWith("enterplace_u_")) {
    return taskPrompt(
      "Route my Claude Code through Enterplace on my own Claude login",
      [["Person token", made.key]],
      [
        '1. In ~/.claude/settings.json, under "env", set ANTHROPIC_BASE_URL to the Enterplace URL above and ANTHROPIC_CUSTOM_HEADERS to "x-enterplace-user: " followed by the person token. Keep every other setting in the file.',
        "2. Make sure ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN are not set, in that file or in my shell profile: with either set, Claude Code stops using my Claude login.",
        "3. Tell me to restart Claude Code: a running session keeps its old address. `/exit` then `claude --continue` keeps the conversation.",
      ],
      `After the restart, one message in Claude Code shows at ${requests} under ${made.name}.`,
      "/integrations/claude-code/",
    );
  }
  return taskPrompt(
    "Point my coding tools at Enterplace",
    [["Enterplace key", made.key]],
    [
      "1. Ask me which coding tools I use, if I have not said.",
      '2. For each, set these lines where it reads them (for Claude Code, under "env" in ~/.claude/settings.json; for others, their settings file or my shell profile), and keep every other setting:',
      "```",
      ...(made.lines ?? [
        `ANTHROPIC_BASE_URL=${base}`,
        `ANTHROPIC_API_KEY=${made.key}`,
      ]),
      "```",
      "3. Tell me to restart each tool: a running session keeps its old address.",
    ],
    `After the restart, one request from each tool shows at ${requests} under ${made.name}.`,
    "/integrations/coding-tools/",
  );
}
