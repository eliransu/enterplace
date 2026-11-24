import type { ComponentType } from "react";
import type { Me } from "@/lib/api";
import { Providers } from "./Providers";
import { McpServers } from "./McpServers";
import { PolicyBasics } from "./PolicyBasics";
import { People } from "./People";
import { Credentials } from "./Credentials";
import { Analytics } from "./Analytics";
import { Requests } from "./Requests";
import { Spend } from "./Spend";
import { Audit } from "./Audit";
import { Start } from "./Start";
import { Prices } from "./Prices";
import { Teams } from "./Teams";
import { McpApprovals, McpSessions, McpTools } from "./Mcp";
import { Deployments } from "./Deployments";
import { PolicyEditor, PolicyVersions, RawPolicy } from "./RawPolicy";

export type PageProps = { me: Me | null; query: URLSearchParams };

// Every page of the app: its # route, its label in the sidebar, and its component.
// `policy`: the page edits the policy, so it says where a change is saved and whether the role may make one.
// `hidden`: reached from another page's actions, not from the sidebar.
// `group`: the sidebar heading it sits under; listed in the order of GROUPS. Start here has none and leads.
export const GROUPS = ["Activity", "Access", "Models", "MCP", "Policy"] as const;
export const PAGES: { route: string; label: string; page: ComponentType<PageProps>; group?: (typeof GROUPS)[number]; policy?: boolean; hidden?: boolean }[] = [
  { route: "/start", label: "Start here", page: Start },
  { route: "/people", group: "Access", label: "People", page: People },
  { route: "/credentials", group: "Access", label: "Credentials", page: Credentials },
  { route: "/analytics", group: "Activity", label: "Analytics", page: Analytics },
  { route: "/spend", group: "Activity", label: "Spend", page: Spend },
  { route: "/audit", group: "Activity", label: "Audit log", page: Audit },
  { route: "/deployments", group: "Policy", label: "Deployments", page: Deployments },
  { route: "/providers", group: "Models", label: "Models and providers", page: Providers, policy: true },
  { route: "/mcp", group: "MCP", label: "MCP servers", page: McpServers, policy: true },
  { route: "/mcp/tools", group: "MCP", label: "MCP tools", page: McpTools },
  { route: "/mcp/approvals", group: "MCP", label: "MCP approvals", page: McpApprovals },
  { route: "/mcp/sessions", group: "MCP", label: "MCP sessions", page: McpSessions },
  { route: "/policy", group: "Policy", label: "Policy basics", page: PolicyBasics, policy: true },
  { route: "/policy/raw", group: "Policy", label: "Raw policy", page: RawPolicy },
  { route: "/policy/versions", label: "Policy versions", page: PolicyVersions, hidden: true },
  { route: "/policy/edit", label: "Edit the policy", page: PolicyEditor, hidden: true },
  { route: "/prices", group: "Models", label: "Prices", page: Prices },
  { route: "/requests", group: "Activity", label: "Requests", page: Requests },
  { route: "/teams", group: "Access", label: "Teams", page: Teams },
];

