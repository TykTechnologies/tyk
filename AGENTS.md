# Gateway agent context

Keep Gateway-specific architecture, configuration, diagnostics, and test guidance in this repository so it can be reviewed with the code it describes. Use the checked-out build and test contracts in `Makefile`, `Taskfile.yml`, and `.taskfiles/` when selecting commands.

For MCP OAuth discovery or client interoperability incidents, use the repository-owned [mcp-oauth-diagnostics skill](.agents/skills/mcp-oauth-diagnostics/SKILL.md). Load its detailed reference only for that workflow; implementation, security review, and test execution retain their own task scope.
