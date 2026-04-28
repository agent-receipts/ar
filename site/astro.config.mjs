import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import rehypeMermaid from "rehype-mermaid";

export default defineConfig({
  site: "https://agentreceipts.ai",
  markdown: {
    syntaxHighlight: {
      type: "shiki",
      excludeLangs: ["mermaid"],
    },
    rehypePlugins: [[rehypeMermaid, { strategy: "inline-svg" }]],
  },
  integrations: [
    starlight({
      title: "Agent Receipts",
      tagline: "Cryptographically signed audit trails for AI agent actions",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/agent-receipts",
        },
      ],
      customCss: ["./src/styles/custom.css"],
      sidebar: [
        {
          label: "Getting Started",
          items: [
            { label: "Introduction", slug: "" },
            { label: "Quick Start", slug: "getting-started/quick-start" },
          ],
        },
        {
          label: "Specification",
          items: [
            { label: "Overview", slug: "specification/overview" },
            {
              label: "How It Works",
              slug: "specification/how-it-works",
            },
            {
              label: "Agent Receipt Schema",
              slug: "specification/agent-receipt-schema",
            },
            {
              label: "Action Taxonomy",
              slug: "specification/action-taxonomy",
            },
            { label: "Risk Levels", slug: "specification/risk-levels" },
            {
              label: "Receipt Chain Verification",
              slug: "specification/receipt-chain-verification",
            },
          ],
        },
        {
          label: "Go SDK",
          items: [
            { label: "Overview", slug: "sdk-go/overview" },
            { label: "Installation", slug: "sdk-go/installation" },
            { label: "API Reference", slug: "sdk-go/api-reference" },
          ],
        },
        {
          label: "TypeScript SDK",
          items: [
            { label: "Overview", slug: "sdk-ts/overview" },
            { label: "Installation", slug: "sdk-ts/installation" },
            { label: "API Reference", slug: "sdk-ts/api-reference" },
          ],
        },
        {
          label: "Python SDK",
          items: [
            { label: "Overview", slug: "sdk-py/overview" },
            { label: "Installation", slug: "sdk-py/installation" },
            { label: "API Reference", slug: "sdk-py/api-reference" },
          ],
        },
        {
          label: "MCP Proxy",
          items: [
            { label: "Overview", slug: "mcp-proxy/overview" },
            { label: "Installation", slug: "mcp-proxy/installation" },
            { label: "Configuration", slug: "mcp-proxy/configuration" },
            { label: "Remote MCP Servers", slug: "mcp-proxy/remote-servers" },
            { label: "Approval Server", slug: "mcp-proxy/approval-ui" },
            { label: "Claude Desktop", slug: "mcp-proxy/claude-desktop" },
            { label: "Claude Code", slug: "mcp-proxy/claude-code" },
            { label: "Codex", slug: "mcp-proxy/codex" },
          ],
        },
        {
          label: "Dashboard",
          items: [
            { label: "Overview", slug: "dashboard/overview" },
            { label: "Installation", slug: "dashboard/installation" },
          ],
        },
        {
          label: "OpenClaw",
          items: [
            { label: "Overview", slug: "openclaw/overview" },
            { label: "Installation", slug: "openclaw/installation" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "CLI Commands", slug: "reference/cli-commands" },
            { label: "Configuration", slug: "reference/configuration" },
          ],
        },
        { label: "Ecosystem", slug: "ecosystem" },
      ],
    }),
  ],
});
