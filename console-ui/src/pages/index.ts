import type { ComponentType } from "react";
import type { LucideIcon } from "lucide-react";
import { ArrowLeftRight, Boxes, Cable, ChartLine, FileCode, Flag, KeyRound, Rocket, Scale, ScrollText, Server, ShieldCheck, Tag, Users, UsersRound, Wallet, Wrench } from "lucide-react";
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
export const PAGES: { route: string; label: string; page: ComponentType<PageProps>; icon?: LucideIcon; group?: (typeof GROUPS)[number]; policy?: boolean; hidden?: boolean }[] = [
  { route: "/start", icon: Flag, label: "Start here", page: Start },
  { route: "/people", icon: Users, group: "Access", label: "People", page: People },
  { route: "/credentials", icon: KeyRound, group: "Access", label: "Credentials", page: Credentials },
  { route: "/analytics", icon: ChartLine, group: "Activity", label: "Analytics", page: Analytics },
  { route: "/spend", icon: Wallet, group: "Activity", label: "Spend", page: Spend },
  { route: "/audit", icon: ScrollText, group: "Activity", label: "Audit log", page: Audit },
  { route: "/deployments", icon: Rocket, group: "Policy", label: "Deployments", page: Deployments },
  { route: "/providers", icon: Boxes, group: "Models", label: "Models and providers", page: Providers, policy: true },
  { route: "/mcp", icon: Server, group: "MCP", label: "MCP servers", page: McpServers, policy: true },
  { route: "/mcp/tools", icon: Wrench, group: "MCP", label: "MCP tools", page: McpTools },
  { route: "/mcp/approvals", icon: ShieldCheck, group: "MCP", label: "MCP approvals", page: McpApprovals },
  { route: "/mcp/sessions", icon: Cable, group: "MCP", label: "MCP sessions", page: McpSessions },
  { route: "/policy", icon: Scale, group: "Policy", label: "Policy basics", page: PolicyBasics, policy: true },
  { route: "/policy/raw", icon: FileCode, group: "Policy", label: "Raw policy", page: RawPolicy },
  { route: "/policy/versions", label: "Policy versions", page: PolicyVersions, hidden: true },
  { route: "/policy/edit", label: "Edit the policy", page: PolicyEditor, hidden: true },
  { route: "/prices", icon: Tag, group: "Models", label: "Prices", page: Prices },
  { route: "/requests", icon: ArrowLeftRight, group: "Activity", label: "Requests", page: Requests },
  { route: "/teams", icon: UsersRound, group: "Access", label: "Teams", page: Teams },
];

