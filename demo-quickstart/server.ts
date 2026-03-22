import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { withMCPI, NodeCryptoProvider } from "@mcp-i/core";
import { z } from "zod";

const server = new McpServer({
  name: "weather-server",
  version: "1.0.0",
});

// Register tools normally — proofs are attached automatically
server.registerTool(
  "get_weather",
  {
    description: "Get current weather for a city",
    inputSchema: { city: z.string().describe("City name") },
  },
  async ({ city }) => ({
    content: [{ type: "text", text: `72°F and sunny in ${city}` }],
  })
);

// One line to add identity + signed proofs
await withMCPI(server, { crypto: new NodeCryptoProvider() });

await server.connect(new StdioServerTransport());
