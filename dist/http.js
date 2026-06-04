import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";
const DB_PATH = process.env.DB_PATH || "/app/data/db/docs.sqlite";
const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
let db = null;
function getDb() {
    if (!db) {
        db = new DatabaseSync(DB_PATH);
        db.prepare("PRAGMA journal_mode=WAL").run();
    }
    return db;
}
function createMcpServer() {
    const mcpServer = new McpServer({
        name: "docs-mcp-server",
        version: "1.0.0",
    });
    mcpServer.tool("search_docs", "Search the documentation using full-text search. Returns matching page titles and snippets.", {
        query: z.string().describe("The search query string"),
        limit: z
            .number()
            .optional()
            .default(10)
            .describe("Maximum number of results to return (default 10)"),
    }, async ({ query, limit }) => {
        const database = getDb();
        const stmt = database.prepare("SELECT p.id, p.title, p.url, p.file_path, snippet(pages_fts, 1, '>>> ', ' <<<', '...', 64) AS snippet FROM pages_fts f JOIN pages p ON p.id = f.rowid WHERE pages_fts MATCH ? ORDER BY rank LIMIT ?");
        const rows = stmt.all(query, limit);
        if (rows.length === 0) {
            return {
                content: [
                    {
                        type: "text",
                        text: `No results found for "${query}".`,
                    },
                ],
            };
        }
        const result = rows
            .map((r, i) => `${i + 1}. **${r.title}**\n   URL: ${r.url}\n   File: ${r.file_path}\n   ${r.snippet}`)
            .join("\n\n");
        return {
            content: [
                {
                    type: "text",
                    text: `Found ${rows.length} result(s) for "${query}":\n\n${result}`,
                },
            ],
        };
    });
    mcpServer.tool("get_page", "Get the full content of a documentation page by its file path or page ID.", {
        identifier: z
            .string()
            .describe("The file path (e.g. 'Trafficking/Core-Objects/006-Campaigns.md') or page ID of the page to retrieve"),
    }, async ({ identifier }) => {
        const database = getDb();
        const stmt = database.prepare("SELECT id, page_id, title, url, depth, file_path, content FROM pages WHERE file_path = ? OR page_id = ? LIMIT 1");
        const row = stmt.get(identifier, identifier);
        if (!row) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Page not found: "${identifier}". Try using search_docs to find the right page.`,
                    },
                ],
            };
        }
        return {
            content: [
                {
                    type: "text",
                    text: `# ${row.title}\n\n**Page ID:** ${row.page_id}\n**URL:** ${row.url}\n**File:** ${row.file_path}\n**Depth:** ${row.depth}\n\n---\n\n${row.content}`,
                },
            ],
        };
    });
    return mcpServer;
}
// --- HTTP Server ---
const app = express();
app.use(express.json());
// Health check endpoint - minimal, no DB query
app.get("/health", (_req, res) => {
    res.status(200).json({ ok: true });
});
// MCP endpoint
app.post("/mcp", async (req, res) => {
    const mcpServer = createMcpServer();
    const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
    });
    try {
        await mcpServer.connect(transport);
        await transport.handleRequest(req, res, req.body);
        res.on("close", () => {
            transport.close();
            mcpServer.close();
        });
    }
    catch (error) {
        console.error("Error handling MCP request:", error);
        if (!res.headersSent) {
            res.status(500).json({
                jsonrpc: "2.0",
                error: { code: -32603, message: "Internal server error" },
                id: null,
            });
        }
    }
});
app.get("/mcp", async (_req, res) => {
    res.writeHead(405).end(JSON.stringify({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Method not allowed." },
        id: null,
    }));
});
app.delete("/mcp", async (_req, res) => {
    res.writeHead(405).end(JSON.stringify({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Method not allowed." },
        id: null,
    }));
});
app.listen(PORT, HOST, () => {
    console.log(`Docs MCP Server listening on ${HOST}:${PORT}`);
    console.log(`Health check: http://${HOST}:${PORT}/health`);
    console.log(`MCP endpoint: http://${HOST}:${PORT}/mcp`);
});
