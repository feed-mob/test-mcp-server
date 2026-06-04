import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { DatabaseSync } from "node:sqlite";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
const DB_PATH = process.env.DB_PATH || "/app/data/db/docs.sqlite";
const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
const AUTH_MODE = process.env.AUTH_MODE || "none";
const BASE_URL = (process.env.BASE_URL || `http://${HOST}:${PORT}`).replace(/\/$/, "");
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN || "feedmob.com";
const SESSION_SECRET = process.env.SESSION_SECRET || GOOGLE_CLIENT_SECRET || "dev-session-secret";
const OAUTH_REDIRECT_URI = `${BASE_URL}/auth/google/callback`;
const SESSION_COOKIE = "docs_mcp_session";
const STATE_COOKIE = "docs_mcp_oauth_state";
let db = null;
function getDb() {
    if (!db) {
        db = new DatabaseSync(DB_PATH, { readOnly: true });
    }
    return db;
}
function parseCookies(header) {
    if (!header)
        return {};
    return Object.fromEntries(header
        .split(";")
        .map((part) => part.trim().split("="))
        .filter(([key, value]) => key && value)
        .map(([key, value]) => [key, decodeURIComponent(value)]));
}
function base64Url(input) {
    return Buffer.from(input)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}
function sign(value) {
    return base64Url(createHmac("sha256", SESSION_SECRET).update(value).digest());
}
function safeEqual(a, b) {
    const left = Buffer.from(a);
    const right = Buffer.from(b);
    return left.length === right.length && timingSafeEqual(left, right);
}
function createSignedToken(payload) {
    const encoded = base64Url(JSON.stringify(payload));
    return `${encoded}.${sign(encoded)}`;
}
function readSession(req) {
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!token)
        return null;
    const [encoded, signature] = token.split(".");
    if (!encoded || !signature || !safeEqual(signature, sign(encoded)))
        return null;
    try {
        const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
        if (!payload.email || payload.exp < Date.now())
            return null;
        return payload;
    }
    catch {
        return null;
    }
}
function setCookie(res, name, value, maxAgeSeconds) {
    const secure = BASE_URL.startsWith("https://") ? "; Secure" : "";
    res.append("Set-Cookie", `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}${secure}`);
}
function clearCookie(res, name) {
    const secure = BASE_URL.startsWith("https://") ? "; Secure" : "";
    res.append("Set-Cookie", `${name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
}
function requireOAuthConfig(res) {
    if (AUTH_MODE !== "oauth")
        return true;
    if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && BASE_URL)
        return true;
    res.status(500).json({ error: "OAuth is not configured" });
    return false;
}
function isAllowedEmail(email) {
    return email.toLowerCase().endsWith(`@${ALLOWED_DOMAIN.toLowerCase()}`);
}
function unauthorized(res) {
    res.status(401).json({
        error: "unauthorized",
        authUrl: `${BASE_URL}/auth/google/login`,
    });
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
app.get("/auth/google/login", (_req, res) => {
    if (!requireOAuthConfig(res))
        return;
    const state = randomBytes(24).toString("hex");
    setCookie(res, STATE_COOKIE, state, 600);
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("client_id", GOOGLE_CLIENT_ID);
    url.searchParams.set("redirect_uri", OAUTH_REDIRECT_URI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("state", state);
    url.searchParams.set("access_type", "offline");
    res.redirect(url.toString());
});
app.get("/auth/google/callback", async (req, res) => {
    if (!requireOAuthConfig(res))
        return;
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    const expectedState = parseCookies(req.headers.cookie)[STATE_COOKIE];
    clearCookie(res, STATE_COOKIE);
    if (!code || !state || !expectedState || state !== expectedState) {
        res.status(400).send("Invalid OAuth state");
        return;
    }
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            code,
            grant_type: "authorization_code",
            redirect_uri: OAUTH_REDIRECT_URI,
        }),
    });
    if (!tokenResponse.ok) {
        res.status(401).send("Google token exchange failed");
        return;
    }
    const tokenJson = (await tokenResponse.json());
    if (!tokenJson.access_token) {
        res.status(401).send("Google access token missing");
        return;
    }
    const userResponse = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });
    if (!userResponse.ok) {
        res.status(401).send("Google user lookup failed");
        return;
    }
    const user = (await userResponse.json());
    const email = user.email || "";
    if (!user.verified_email || !isAllowedEmail(email)) {
        res.status(403).send(`Only @${ALLOWED_DOMAIN} accounts are allowed`);
        return;
    }
    setCookie(res, SESSION_COOKIE, createSignedToken({ email, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }), 7 * 24 * 60 * 60);
    res.redirect("/");
});
app.get("/auth/logout", (_req, res) => {
    clearCookie(res, SESSION_COOKIE);
    res.redirect("/");
});
app.get("/", (req, res) => {
    const session = readSession(req);
    res.status(200).json({
        ok: true,
        authMode: AUTH_MODE,
        user: session?.email || null,
        mcp: "/mcp",
    });
});
// MCP endpoint
app.post("/mcp", async (req, res) => {
    if (AUTH_MODE === "oauth" && !readSession(req)) {
        unauthorized(res);
        return;
    }
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
