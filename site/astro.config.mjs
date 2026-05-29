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
      head: [
        {
          tag: "link",
          attrs: {
            rel: "me",
            href: "https://github.com/agent-receipts",
          },
        },
        {
          tag: "script",
          attrs: { type: "application/ld+json" },
          content: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "WebSite",
            name: "Agent Receipts",
            url: "https://agentreceipts.ai",
            publisher: {
              "@type": "Organization",
              name: "Agent Receipts",
              url: "https://agentreceipts.ai",
              sameAs: ["https://github.com/agent-receipts"],
            },
          }),
        },
      ],
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/agent-receipts",
        },
      ],
      components: {
        SocialIcons: "./src/components/SocialIcons.astro",
      },
      customCss: ["./src/styles/custom.css"],
      sidebar: [
        {
          label: "Getting Started",
          items: [
            { label: "Introduction", slug: "" },
            { label: "Quick Start", slug: "getting-started/quick-start" },
            { label: "Daemon Setup", slug: "getting-started/daemon-setup" },
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
          label: "Spec (full text)",
          link: "/spec/",
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
          label: "Deployment",
          items: [
            {
              label: "Ephemeral Compute",
              slug: "deployment/ephemeral-compute",
            },
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
            { label: "Cursor", slug: "mcp-proxy/cursor" },
            { label: "Windsurf", slug: "mcp-proxy/windsurf" },
            { label: "VS Code Copilot", slug: "mcp-proxy/vscode-copilot" },
            {
              label: "JetBrains AI Assistant",
              slug: "mcp-proxy/jetbrains",
            },
            { label: "Cline", slug: "mcp-proxy/cline" },
          ],
        },
        {
          label: "Hook",
          items: [
            { label: "Overview", slug: "hook/overview" },
            { label: "Installation", slug: "hook/installation" },
            { label: "Claude Code", slug: "hook/claude-code" },
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
            { label: "CLI Reference", slug: "openclaw/cli-reference" },
            { label: "Agent Tools", slug: "openclaw/agent-tools" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "CLI Commands", slug: "reference/cli-commands" },
            { label: "Configuration", slug: "reference/configuration" },
          ],
        },
        {
          label: "Ecosystem",
          items: [
            { label: "Overview", slug: "ecosystem" },
            {
              label: "Landscape (living)",
              slug: "ecosystem/landscape",
            },
          ],
        },
        {
          label: "Blog",
          items: [
            { label: "All Posts", slug: "blog" },
            {
              label: "Agent Security Tooling Landscape — May 2026",
              slug: "blog/agent-security-tooling-landscape-may-2026",
            },
            {
              label: "The audit boundary belongs outside the agent",
              slug: "blog/daemon-process-separation",
            },
            {
              label: "OpenClaw Plugin: How It Works",
              slug: "blog/openclaw-plugin-deep-dive",
            },
            {
              label: "Agent Security Tooling Landscape — April 2026",
              slug: "blog/agent-security-tooling-landscape-april-2026",
            },
          ],
        },
      ],
    }),
  ],
});
