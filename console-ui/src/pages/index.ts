import type { ComponentType } from "react";
import type { Me } from "@/lib/api";
import { Providers } from "./Providers";
import { McpServers } from "./McpServers";
import { PolicyBasics } from "./PolicyBasics";
import { People } from "./People";

export type PageProps = { me: Me | null; query: URLSearchParams };

// Every page of the app: its # route, its label in the sidebar, and its component. A ported page adds one line here
// and takes its line out of SERVER_PAGES below.
// `policy`: the page edits the policy, so it says where a change is saved and whether the role may make one.
export const PAGES: { route: string; label: string; page: ComponentType<PageProps>; policy?: boolean }[] = [
  { route: "/people", label: "People", page: People },
  { route: "/providers", label: "Models and providers", page: Providers, policy: true },
  { route: "/mcp", label: "MCP servers", page: McpServers, policy: true },
  { route: "/policy", label: "Policy basics", page: PolicyBasics, policy: true },
];

// The pages the console still renders on the server, linked as they are, by sidebar group.
export const SERVER_PAGES: [string, [string, string][]][] = [
  ["", [["/console/start", "Start here"]]],
  ["Activity", [["/console/requests", "Requests"], ["/console/audit", "Audit log"], ["/console/analytics", "Analytics"], ["/console/spend", "Spend"]]],
  ["Access", [["/console/teams", "Teams"], ["/console/policy", "Raw policy"], ["/console/models", "Prices"], ["/console/credentials", "Credentials"]]],
  ["Tools", [["/console/mcp/tools", "MCP tools"], ["/console/mcp/approvals", "MCP approvals"]]],
];
