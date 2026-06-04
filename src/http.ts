import express, { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { DatabaseSync } from "node:sqlite";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
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

let db: DatabaseSync | null = null;

function getDb(): DatabaseSync {
  if (!db) {
    db = new DatabaseSync(DB_PATH, { readOnly: true });
  }
  return db;
}

type GoogleUser = {
  email?: string;
  verified_email?: boolean;
};

type SessionPayload = {
  email: string;
  exp: number;
};

type OAuthClient = {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  client_name?: string;
  scope?: string;
  client_id_issued_at: number;
  client_secret_expires_at?: number;
};

type OAuthAuthorization = {
  client_id: string;
  redirect_uri: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  resource?: string;
};

type OAuthCode = OAuthAuthorization & {
  email: string;
  exp: number;
};

type AccessToken = {
  email: string;
  exp: number;
};

const oauthClients = new Map<string, OAuthClient>();
const pendingOAuthStates = new Map<string, OAuthAuthorization>();
const authorizationCodes = new Map<string, OAuthCode>();
const accessTokens = new Map<string, AccessToken>();

function parseCookies(header: string | undefined): Record<string, string> {
  if (!header) return {};
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim().split("="))
      .filter(([key, value]) => key && value)
      .map(([key, value]) => [key, decodeURIComponent(value)])
  );
}

function base64Url(input: string | Buffer): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function sign(value: string): string {
  return base64Url(createHmac("sha256", SESSION_SECRET).update(value).digest());
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function createSignedToken(payload: SessionPayload): string {
  const encoded = base64Url(JSON.stringify(payload));
  return `${encoded}.${sign(encoded)}`;
}

function readSession(req: Request): SessionPayload | null {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!token) return null;

  const [encoded, signature] = token.split(".");
  if (!encoded || !signature || !safeEqual(signature, sign(encoded))) return null;

  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as SessionPayload;
    if (!payload.email || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function setCookie(res: Response, name: string, value: string, maxAgeSeconds: number): void {
  const secure = BASE_URL.startsWith("https://") ? "; Secure" : "";
  res.append(
    "Set-Cookie",
    `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}${secure}`
  );
}

function clearCookie(res: Response, name: string): void {
  const secure = BASE_URL.startsWith("https://") ? "; Secure" : "";
  res.append("Set-Cookie", `${name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
}

function requireOAuthConfig(res: Response): boolean {
  if (AUTH_MODE !== "oauth") return true;
  if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && BASE_URL) return true;
  res.status(500).json({ error: "OAuth is not configured" });
  return false;
}

function isAllowedEmail(email: string): boolean {
  return email.toLowerCase().endsWith(`@${ALLOWED_DOMAIN.toLowerCase()}`);
}

function oauthMetadata() {
  return {
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    scopes_supported: ["openid", "email", "profile"],
  };
}

function protectedResourceMetadata() {
  return {
    resource: `${BASE_URL}/mcp`,
    authorization_servers: [BASE_URL],
    scopes_supported: ["openid", "email", "profile"],
    bearer_methods_supported: ["header"],
    resource_name: "Docs MCP Server",
  };
}

function readBearerToken(req: Request): AccessToken | null {
  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = accessTokens.get(match[1]);
  if (!token || token.exp < Date.now()) return null;
  return token;
}

function unauthorized(res: Response): void {
  res.setHeader(
    "WWW-Authenticate",
    `Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource/mcp"`
  );
  res.status(401).json({
    error: "unauthorized",
    authUrl: `${BASE_URL}/auth/google/login`,
  });
}

function redirectWithOAuthError(res: Response, redirectUri: string, error: string, state?: string): void {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (state) url.searchParams.set("state", state);
  res.redirect(url.toString());
}

async function exchangeGoogleCode(code: string, redirectUri: string): Promise<GoogleUser | null> {
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    }),
  });

  if (!tokenResponse.ok) return null;

  const tokenJson = (await tokenResponse.json()) as { access_token?: string };
  if (!tokenJson.access_token) return null;

  const userResponse = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${tokenJson.access_token}` },
  });

  if (!userResponse.ok) return null;
  return (await userResponse.json()) as GoogleUser;
}

function verifyPkce(codeVerifier: string, codeChallenge: string, method = "S256"): boolean {
  if (method !== "S256") return false;
  const actual = base64Url(createHash("sha256").update(codeVerifier).digest());
  return safeEqual(actual, codeChallenge);
}

function createMcpServer(): McpServer {
  const mcpServer = new McpServer({
    name: "docs-mcp-server",
    version: "1.0.0",
  });

  mcpServer.tool(
    "search_docs",
    "Search the documentation using full-text search. Returns matching page titles and snippets.",
    {
      query: z.string().describe("The search query string"),
      limit: z
        .number()
        .optional()
        .default(10)
        .describe("Maximum number of results to return (default 10)"),
    },
    async ({ query, limit }) => {
      const database = getDb();
      const stmt = database.prepare(
        "SELECT p.id, p.title, p.url, p.file_path, snippet(pages_fts, 1, '>>> ', ' <<<', '...', 64) AS snippet FROM pages_fts f JOIN pages p ON p.id = f.rowid WHERE pages_fts MATCH ? ORDER BY rank LIMIT ?"
      );
      const rows = stmt.all(query, limit) as Array<{
        id: number;
        title: string;
        url: string;
        file_path: string;
        snippet: string;
      }>;

      if (rows.length === 0) {
        return {
          content: [
            {
              type: "text" as const,
              text: `No results found for "${query}".`,
            },
          ],
        };
      }

      const result = rows
        .map(
          (r, i) =>
            `${i + 1}. **${r.title}**\n   URL: ${r.url}\n   File: ${r.file_path}\n   ${r.snippet}`
        )
        .join("\n\n");

      return {
        content: [
          {
            type: "text" as const,
            text: `Found ${rows.length} result(s) for "${query}":\n\n${result}`,
          },
        ],
      };
    }
  );

  mcpServer.tool(
    "get_page",
    "Get the full content of a documentation page by its file path or page ID.",
    {
      identifier: z
        .string()
        .describe(
          "The file path (e.g. 'Trafficking/Core-Objects/006-Campaigns.md') or page ID of the page to retrieve"
        ),
    },
    async ({ identifier }) => {
      const database = getDb();
      const stmt = database.prepare(
        "SELECT id, page_id, title, url, depth, file_path, content FROM pages WHERE file_path = ? OR page_id = ? LIMIT 1"
      );
      const row = stmt.get(identifier, identifier) as {
        id: number;
        page_id: string;
        title: string;
        url: string;
        depth: number;
        file_path: string;
        content: string;
      } | null;

      if (!row) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Page not found: "${identifier}". Try using search_docs to find the right page.`,
            },
          ],
        };
      }

      return {
        content: [
          {
            type: "text" as const,
            text: `# ${row.title}\n\n**Page ID:** ${row.page_id}\n**URL:** ${row.url}\n**File:** ${row.file_path}\n**Depth:** ${row.depth}\n\n---\n\n${row.content}`,
          },
        ],
      };
    }
  );

  return mcpServer;
}

// --- HTTP Server ---

const app = express();
app.use(express.json());

// Health check endpoint - minimal, no DB query
app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({ ok: true });
});

app.get("/.well-known/oauth-authorization-server", (_req: Request, res: Response) => {
  res.json(oauthMetadata());
});

app.get("/.well-known/oauth-protected-resource/mcp", (_req: Request, res: Response) => {
  res.json(protectedResourceMetadata());
});

app.post("/register", (req: Request, res: Response) => {
  const body = req.body as {
    redirect_uris?: string[];
    token_endpoint_auth_method?: string;
    client_name?: string;
    scope?: string;
  };

  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
    res.status(400).json({ error: "invalid_client_metadata", error_description: "redirect_uris is required" });
    return;
  }

  const clientId = randomBytes(16).toString("hex");
  const isPublic = body.token_endpoint_auth_method === "none";
  const client: OAuthClient = {
    client_id: clientId,
    client_secret: isPublic ? undefined : randomBytes(32).toString("hex"),
    redirect_uris: body.redirect_uris,
    token_endpoint_auth_method: body.token_endpoint_auth_method || (isPublic ? "none" : "client_secret_post"),
    client_name: body.client_name,
    scope: body.scope,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: isPublic ? undefined : Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
  };
  oauthClients.set(clientId, client);

  res.status(201).json(client);
});

app.get("/auth/google/login", (_req: Request, res: Response) => {
  if (!requireOAuthConfig(res)) return;

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

app.get("/authorize", (req: Request, res: Response) => {
  if (!requireOAuthConfig(res)) return;

  const clientId = String(req.query.client_id || "");
  const redirectUri = String(req.query.redirect_uri || "");
  const responseType = String(req.query.response_type || "");
  const state = req.query.state ? String(req.query.state) : undefined;
  const codeChallenge = req.query.code_challenge ? String(req.query.code_challenge) : undefined;
  const codeChallengeMethod = req.query.code_challenge_method
    ? String(req.query.code_challenge_method)
    : undefined;
  const resource = req.query.resource ? String(req.query.resource) : undefined;

  const client = oauthClients.get(clientId);
  if (!client || !client.redirect_uris.includes(redirectUri) || responseType !== "code") {
    if (redirectUri) redirectWithOAuthError(res, redirectUri, "invalid_request", state);
    else res.status(400).json({ error: "invalid_request" });
    return;
  }

  const oauthState = randomBytes(24).toString("hex");
  pendingOAuthStates.set(oauthState, {
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    resource,
  });
  setCookie(res, STATE_COOKIE, oauthState, 600);

  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", GOOGLE_CLIENT_ID);
  url.searchParams.set("redirect_uri", OAUTH_REDIRECT_URI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", oauthState);
  res.redirect(url.toString());
});

app.get("/auth/google/callback", async (req: Request, res: Response) => {
  if (!requireOAuthConfig(res)) return;

  const code = String(req.query.code || "");
  const state = String(req.query.state || "");
  const expectedState = parseCookies(req.headers.cookie)[STATE_COOKIE];
  clearCookie(res, STATE_COOKIE);

  if (!code || !state || !expectedState || state !== expectedState) {
    res.status(400).send("Invalid OAuth state");
    return;
  }

  const user = await exchangeGoogleCode(code, OAUTH_REDIRECT_URI);
  if (!user) {
    res.status(401).send("Google user lookup failed");
    return;
  }

  const email = user.email || "";
  if (!user.verified_email || !isAllowedEmail(email)) {
    res.status(403).send(`Only @${ALLOWED_DOMAIN} accounts are allowed`);
    return;
  }

  const pending = pendingOAuthStates.get(state);
  if (pending) {
    pendingOAuthStates.delete(state);
    const oauthCode = randomBytes(24).toString("hex");
    authorizationCodes.set(oauthCode, {
      ...pending,
      email,
      exp: Date.now() + 10 * 60 * 1000,
    });

    const redirectUrl = new URL(pending.redirect_uri);
    redirectUrl.searchParams.set("code", oauthCode);
    if (pending.state) redirectUrl.searchParams.set("state", pending.state);
    res.redirect(redirectUrl.toString());
    return;
  }

  setCookie(
    res,
    SESSION_COOKIE,
    createSignedToken({ email, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }),
    7 * 24 * 60 * 60
  );
  res.redirect("/");
});

app.post("/token", express.urlencoded({ extended: false }), (req: Request, res: Response) => {
  const body = req.body as {
    grant_type?: string;
    code?: string;
    client_id?: string;
    client_secret?: string;
    code_verifier?: string;
    redirect_uri?: string;
  };

  if (body.grant_type !== "authorization_code" || !body.code || !body.client_id) {
    res.status(400).json({ error: "invalid_request" });
    return;
  }

  const client = oauthClients.get(body.client_id);
  const authCode = authorizationCodes.get(body.code);
  if (!client || !authCode || authCode.exp < Date.now() || authCode.client_id !== body.client_id) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  if (authCode.redirect_uri !== body.redirect_uri) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  if (client.client_secret && client.client_secret !== body.client_secret) {
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  if (authCode.code_challenge) {
    if (!body.code_verifier || !verifyPkce(body.code_verifier, authCode.code_challenge, authCode.code_challenge_method)) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
  }

  authorizationCodes.delete(body.code);
  const accessToken = randomBytes(32).toString("hex");
  accessTokens.set(accessToken, {
    email: authCode.email,
    exp: Date.now() + 60 * 60 * 1000,
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "openid email profile",
  });
});

app.get("/auth/logout", (_req: Request, res: Response) => {
  clearCookie(res, SESSION_COOKIE);
  res.redirect("/");
});

app.get("/", (req: Request, res: Response) => {
  const session = readSession(req);
  res.status(200).json({
    ok: true,
    authMode: AUTH_MODE,
    user: session?.email || null,
    mcp: "/mcp",
  });
});

// MCP endpoint
app.post("/mcp", async (req: Request, res: Response) => {
  if (AUTH_MODE === "oauth" && !readSession(req) && !readBearerToken(req)) {
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
  } catch (error) {
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

app.get("/mcp", async (_req: Request, res: Response) => {
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed." },
      id: null,
    })
  );
});

app.delete("/mcp", async (_req: Request, res: Response) => {
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed." },
      id: null,
    })
  );
});

app.listen(PORT, HOST, () => {
  console.log(`Docs MCP Server listening on ${HOST}:${PORT}`);
  console.log(`Health check: http://${HOST}:${PORT}/health`);
  console.log(`MCP endpoint: http://${HOST}:${PORT}/mcp`);
});
