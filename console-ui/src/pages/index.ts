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
import { PolicyEditor, PolicyVersions, RawPolicy } from "./RawPolicy";

export type PageProps = { me: Me | null; query: URLSearchParams };

// Every page of the app: its # route, its label in the sidebar, and its component.
// `policy`: the page edits the policy, so it says where a change is saved and whether the role may make one.
// `hidden`: reached from another page's actions, not from the sidebar.
export const PAGES: { route: string; label: string; page: ComponentType<PageProps>; policy?: boolean; hidden?: boolean }[] = [
  { route: "/start", label: "Start here", page: Start },
  { route: "/people", label: "People", page: People },
  { route: "/credentials", label: "Credentials", page: Credentials },
  { route: "/analytics", label: "Analytics", page: Analytics },
  { route: "/spend", label: "Spend", page: Spend },
  { route: "/audit", label: "Audit log", page: Audit },
  { route: "/providers", label: "Models and providers", page: Providers, policy: true },
  { route: "/mcp", label: "MCP servers", page: McpServers, policy: true },
  { route: "/mcp/tools", label: "MCP tools", page: McpTools },
  { route: "/mcp/approvals", label: "MCP approvals", page: McpApprovals },
  { route: "/mcp/sessions", label: "MCP sessions", page: McpSessions },
  { route: "/policy", label: "Policy basics", page: PolicyBasics, policy: true },
  { route: "/policy/raw", label: "Raw policy", page: RawPolicy },
  { route: "/policy/versions", label: "Policy versions", page: PolicyVersions, hidden: true },
  { route: "/policy/edit", label: "Edit the policy", page: PolicyEditor, hidden: true },
  { route: "/prices", label: "Prices", page: Prices },
  { route: "/requests", label: "Requests", page: Requests },
  { route: "/teams", label: "Teams", page: Teams },
];

