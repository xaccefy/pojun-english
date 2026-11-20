import {
  Activity,
  Ban,
  BellRing,
  Bot,
  Brain,
  Cable,
  Bug,
  ClipboardList,
  FolderOpen,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  MonitorCog,
  Plug,
  Radio,
  RadioTower,
  ScrollText,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Terminal,
  Wrench,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "Features",
    items: [
      { id: "dashboard", title: "Dashboard", url: "/dashboard", icon: LayoutDashboard },
      { id: "chat", title: "Chat", url: "/chat", icon: MessageSquare },
      { id: "tasks", title: "Tasks", url: "/function/tasks", icon: Target },
      { id: "findings", title: "Findings", url: "/function/findings", icon: Bug },
      { id: "traffic", title: "Traffic", url: "/function/traffic", icon: Activity },
      { id: "commands", title: "Tool runs", url: "/function/commands", icon: Terminal },
      { id: "llm-records", title: "LLM records", url: "/function/llm-records", icon: Radio },
      { id: "assets", title: "Assets", url: "/function/assets", icon: Network },
      { id: "sync", title: "Asset sync", url: "/function/sync", icon: FolderSync },
      { id: "workspace", title: "Workspace", url: "/function/workspace", icon: FolderOpen },
    ],
  },
  {
    id: 2,
    label: "System",
    items: [
      { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
      { id: "agents", title: "Agent", url: "/system/agents", icon: Bot },
      { id: "mcp", title: "MCP", url: "/system/mcp", icon: Plug },
      { id: "skills", title: "Skill", url: "/system/skills", icon: Sparkles },
      { id: "tools", title: "Tools", url: "/system/tools", icon: Wrench },
      { id: "notify", title: "Notifications", url: "/system/notify", icon: BellRing },
      { id: "vulnintel", title: "Vuln intel", url: "/system/vulnintel", icon: ShieldCheck },
      { id: "proxypool", title: "Proxy pool", url: "/system/proxypool", icon: Network },
      { id: "clash-nodes", title: "Clash nodes", url: "/system/proxypool/clash", icon: Network, badge: "new" },
      { id: "egress", title: "SSH jump hosts", url: "/system/egress", icon: Cable },
      { id: "hostenv", title: "Host environment", url: "/system/hostenv", icon: MonitorCog },
      { id: "c2", title: "Listeners / C2", url: "/system/c2", icon: RadioTower },
      { id: "intercept", title: "Intercept rules", url: "/system/intercept", icon: ShieldAlert },
      { id: "asset-intercept", title: "Asset intercept", url: "/system/intercept/assets", icon: Ban },
      { id: "approvals", title: "Intercept approvals", url: "/system/intercept/approvals", icon: ClipboardList },
      { id: "logs", title: "Logs", url: "/system/logs", icon: ScrollText },
      { id: "settings", title: "System settings", url: "/system/settings", icon: Settings2 },
    ],
  },
];
