import type { ComponentType } from "react";
import type { LucideIcon } from "lucide-react";
import {
  ArrowLeftRight,
  Blocks,
  Boxes,
  ChartLine,
  LayoutDashboard,
  Rocket,
  Scale,
  ScrollText,
  Server,
  SquareTerminal,
  Users,
} from "lucide-react";
import type { Me } from "@/lib/api";
import { Overview } from "./Overview";
import { USE_CASE_PAGES } from "./Setup";
import { Coding } from "./Coding";
import { Apps } from "./Apps";
import { Providers } from "./Providers";
import { McpServers } from "./McpServers";
import { McpApprovals, McpSessions, McpTools } from "./Mcp";
import { PolicyBasics } from "./PolicyBasics";
import { PolicyEditor, PolicyVersions, RawPolicy } from "./RawPolicy";
import { People } from "./People";
import { Teams } from "./Teams";
import { Credentials } from "./Credentials";
import { Analytics } from "./Analytics";
import { Spend } from "./Spend";
import { Requests } from "./Requests";
import { Audit } from "./Audit";
import { Prices } from "./Prices";
import { Deployments } from "./Deployments";

export type PageProps = { me: Me | null; query: URLSearchParams };

// One # route of the app. `policy`: the page edits the policy, so the shell says where a change is saved and whether
// the role may make one. `hidden`: reached from another page's actions, not shown as a tab.
export type Tab = {
  route: string;
  label: string;
  page: ComponentType<PageProps>;
  policy?: boolean;
  hidden?: boolean;
};

// One sidebar entry: a page, or a few pages shown as tabs under one entry. Grouped by what the admin is doing: the
// use cases first, then what happened, then the settings every use case shares.
export type Section = {
  label: string;
  icon: LucideIcon;
  group?: (typeof GROUPS)[number];
  tabs: Tab[];
};

export const GROUPS = ["Use cases", "Activity", "Settings"] as const;

export const SECTIONS: Section[] = [
  {
    label: "Overview",
    icon: LayoutDashboard,
    tabs: [{ route: "/overview", label: "Overview", page: Overview }],
  },
  {
    label: "Coding agents",
    icon: SquareTerminal,
    group: "Use cases",
    tabs: [{ route: "/coding", label: "Coding agents", page: Coding }],
  },
  {
    label: "Apps and agents",
    icon: Blocks,
    group: "Use cases",
    tabs: [{ route: "/apps", label: "Apps and agents", page: Apps }],
  },
  {
    label: "MCP tools",
    icon: Server,
    group: "Use cases",
    tabs: [
      { route: "/mcp", label: "Servers", page: McpServers, policy: true },
      { route: "/mcp/tools", label: "Tools", page: McpTools },
      { route: "/mcp/approvals", label: "Approvals", page: McpApprovals },
      { route: "/mcp/sessions", label: "Sessions", page: McpSessions },
    ],
  },
  {
    label: "Requests",
    icon: ArrowLeftRight,
    group: "Activity",
    tabs: [{ route: "/requests", label: "Requests", page: Requests }],
  },
  {
    label: "Usage",
    icon: ChartLine,
    group: "Activity",
    tabs: [
      { route: "/usage", label: "Analytics", page: Analytics },
      { route: "/usage/spend", label: "Spend this month", page: Spend },
    ],
  },
  {
    label: "Audit log",
    icon: ScrollText,
    group: "Activity",
    tabs: [{ route: "/audit", label: "Audit log", page: Audit }],
  },
  {
    label: "People and teams",
    icon: Users,
    group: "Settings",
    tabs: [
      { route: "/people", label: "People", page: People },
      { route: "/teams", label: "Teams", page: Teams },
    ],
  },
  {
    label: "Models and providers",
    icon: Boxes,
    group: "Settings",
    tabs: [
      {
        route: "/providers",
        label: "Providers",
        page: Providers,
        policy: true,
      },
      { route: "/prices", label: "Models and prices", page: Prices },
      { route: "/credentials", label: "Provider keys", page: Credentials },
    ],
  },
  {
    label: "Policy",
    icon: Scale,
    group: "Settings",
    tabs: [
      {
        route: "/policy",
        label: "Rules and limits",
        page: PolicyBasics,
        policy: true,
      },
      { route: "/policy/raw", label: "Policy file", page: RawPolicy },
      { route: "/policy/versions", label: "Versions", page: PolicyVersions },
      {
        route: "/policy/edit",
        label: "Edit the file",
        page: PolicyEditor,
        hidden: true,
      },
    ],
  },
  {
    label: "Health",
    icon: Rocket,
    group: "Settings",
    tabs: [{ route: "/deployments", label: "Health", page: Deployments }],
  },
];

// Routes that moved: an old link, bookmark or server redirect lands on the new place with its query. Start here's
// checklist of a use case is on that use case's page now.
const MOVED: Record<string, string> = {
  "/start": "/overview",
  "/analytics": "/usage",
  "/spend": "/usage/spend",
};

export function moved(route: string, query: URLSearchParams): string | undefined {
  if (route === "/start") return USE_CASE_PAGES[query.get("track") ?? ""] ?? MOVED[route];
  return MOVED[route];
}

export const HOME = "/overview";

export function find(route: string): { section: Section; tab: Tab } {
  for (const section of SECTIONS) {
    const tab = section.tabs.find((t) => t.route === route);
    if (tab) return { section, tab };
  }
  return { section: SECTIONS[0], tab: SECTIONS[0].tabs[0] };
}
