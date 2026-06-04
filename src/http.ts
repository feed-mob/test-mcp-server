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
const TOKEN_SECRET = process.env.TOKEN_SECRET || SESSION_SECRET;
const OAUTH_REDIRECT_URI = `${BASE_URL}/auth/google/callback`;
const SESSION_COOKIE = "docs_mcp_session";
const STATE_COOKIE = "docs_mcp_oauth_state";
const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_CODE_TTL_SECONDS = 10 * 60;
const DEVICE_CODE_INTERVAL_SECONDS = 5;
const ACCESS_TOKEN_TTL_SECONDS = parseInt(process.env.ACCESS_TOKEN_TTL_SECONDS || "86400", 10);
const REFRESH_TOKEN_TTL_SECONDS = parseInt(process.env.REFRESH_TOKEN_TTL_SECONDS || "7776000", 10);
const DEFAULT_SCOPE = "openid email profile";

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
  client_secret_hash?: string;
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  client_name?: string;
  scope?: string;
  grant_types?: string[];
  response_types?: string[];
  client_id_issued_at: number;
  client_secret_expires_at?: number;
};

type OAuthAuthorization = {
  client_id: string;
  redirect_uri: string;
  state?: string;
  scope?: string;
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

type OAuthTokenPayload = {
  typ: "access" | "refresh";
  email: string;
  client_id: string;
  scope: string;
  iat: number;
  exp: number;
  client_secret_hash?: string;
};

type DeviceAuthorization = {
  client_id: string;
  device_code: string;
  user_code: string;
  scope?: string;
  resource?: string;
  email?: string;
  status: "pending" | "approved" | "denied";
  exp: number;
  intervalSeconds: number;
  lastPollAt?: number;
};

type ClientCredentials = {
  client_id?: string;
  client_secret?: string;
};

type SignedClientPayload = {
  typ: "client";
  jti: string;
  client_secret_hash?: string;
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  client_name?: string;
  scope?: string;
  grant_types?: string[];
  response_types?: string[];
  client_id_issued_at: number;
  client_secret_expires_at?: number;
};

const oauthClients = new Map<string, OAuthClient>();
const pendingOAuthStates = new Map<string, OAuthAuthorization>();
const pendingDeviceOAuthStates = new Map<string, string>();
const authorizationCodes = new Map<string, OAuthCode>();
const deviceAuthorizations = new Map<string, DeviceAuthorization>();
const deviceCodesByUserCode = new Map<string, string>();

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

function signWithSecret(value: string, secret: string): string {
  return base64Url(createHmac("sha256", secret).update(value).digest());
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

function createOAuthToken(payload: Omit<OAuthTokenPayload, "iat" | "exp">, ttlSeconds: number): string {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const encoded = base64Url(
    JSON.stringify({
      ...payload,
      iat: nowSeconds,
      exp: nowSeconds + ttlSeconds,
    })
  );
  return `${encoded}.${signWithSecret(encoded, TOKEN_SECRET)}`;
}

function readOAuthToken(token: string, expectedType: OAuthTokenPayload["typ"]): OAuthTokenPayload | null {
  const [encoded, signature] = token.split(".");
  if (!encoded || !signature || !safeEqual(signature, signWithSecret(encoded, TOKEN_SECRET))) return null;

  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as OAuthTokenPayload;
    if (payload.typ !== expectedType || !payload.email || !payload.client_id || !payload.scope) return null;
    if (payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function createSignedClientId(payload: SignedClientPayload): string {
  const encoded = base64Url(JSON.stringify(payload));
  return `${encoded}.${signWithSecret(encoded, TOKEN_SECRET)}`;
}

function readSignedClient(clientId: string): OAuthClient | null {
  const [encoded, signature] = clientId.split(".");
  if (!encoded || !signature || !safeEqual(signature, signWithSecret(encoded, TOKEN_SECRET))) return null;

  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as SignedClientPayload;
    if (payload.typ !== "client" || !payload.jti || !Array.isArray(payload.redirect_uris)) return null;
    if (payload.client_secret_expires_at && payload.client_secret_expires_at < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return {
      client_id: clientId,
      client_secret_hash: payload.client_secret_hash,
      redirect_uris: payload.redirect_uris,
      token_endpoint_auth_method: payload.token_endpoint_auth_method,
      client_name: payload.client_name,
      scope: payload.scope,
      grant_types: payload.grant_types,
      response_types: payload.response_types,
      client_id_issued_at: payload.client_id_issued_at,
      client_secret_expires_at: payload.client_secret_expires_at,
    };
  } catch {
    return null;
  }
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
    device_authorization_endpoint: `${BASE_URL}/device_authorization`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", DEVICE_CODE_GRANT, "refresh_token"],
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

function clientSecretHash(client: OAuthClient): string | undefined {
  if (client.client_secret_hash) return client.client_secret_hash;
  if (!client.client_secret) return undefined;
  return base64Url(createHash("sha256").update(client.client_secret).digest());
}

function hashClientSecret(secret: string): string {
  return base64Url(createHash("sha256").update(secret).digest());
}

function getOAuthClient(clientId: string): OAuthClient | null {
  return oauthClients.get(clientId) || readSignedClient(clientId);
}

function authenticateClient(body: ClientCredentials): OAuthClient | null {
  if (!body.client_id) return null;

  const client = getOAuthClient(body.client_id);
  if (!client) return null;

  if (client.client_secret && client.client_secret !== body.client_secret) return null;
  if (client.client_secret_hash && (!body.client_secret || hashClientSecret(body.client_secret) !== client.client_secret_hash)) {
    return null;
  }
  return client;
}

function issueTokenResponse(client: OAuthClient, email: string, scope = DEFAULT_SCOPE) {
  return issueTokenResponseFromPayload({
    email,
    client_id: client.client_id,
    scope,
    client_secret_hash: clientSecretHash(client),
  });
}

function issueTokenResponseFromPayload(tokenPayload: Omit<OAuthTokenPayload, "typ" | "iat" | "exp">) {
  return {
    access_token: createOAuthToken({ typ: "access", ...tokenPayload }, ACCESS_TOKEN_TTL_SECONDS),
    refresh_token: createOAuthToken({ typ: "refresh", ...tokenPayload }, REFRESH_TOKEN_TTL_SECONDS),
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    scope: tokenPayload.scope,
  };
}

function readBearerToken(req: Request): AccessToken | null {
  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = readOAuthToken(match[1], "access");
  if (!token) return null;

  const client = getOAuthClient(token.client_id);
  if (client?.client_secret && token.client_secret_hash !== clientSecretHash(client)) return null;
  return { email: token.email, exp: token.exp * 1000 };
}

function unauthorized(res: Response): void {
  res.setHeader(
    "WWW-Authenticate",
    `Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource/mcp"`
  );
  res.status(401).json({
    error: "unauthorized",
    authUrl: `${BASE_URL}/login`,
  });
}

function redirectWithOAuthError(res: Response, redirectUri: string, error: string, state?: string): void {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (state) url.searchParams.set("state", state);
  res.redirect(url.toString());
}

function htmlPage(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    :root { color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f7fb; color: #172033; }
    main { width: min(560px, calc(100vw - 32px)); padding: 32px; background: white; border: 1px solid #d8dee9; border-radius: 8px; box-shadow: 0 10px 30px rgb(15 23 42 / 12%); }
    h1 { margin: 0 0 16px; font-size: 24px; line-height: 1.2; }
    p { line-height: 1.55; }
    a, button { display: inline-flex; align-items: center; min-height: 40px; padding: 0 14px; border: 1px solid #1f6feb; border-radius: 6px; background: #1f6feb; color: white; text-decoration: none; font: inherit; cursor: pointer; }
    input { width: 100%; box-sizing: border-box; min-height: 44px; padding: 8px 12px; border: 1px solid #b8c0cc; border-radius: 6px; font: inherit; text-transform: uppercase; letter-spacing: 0.04em; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 18px; }
    .secondary { background: white; color: #1f6feb; }
    .code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 30px; letter-spacing: 0.12em; }
    @media (prefers-color-scheme: dark) {
      body { background: #0d1117; color: #e6edf3; }
      main { background: #161b22; border-color: #30363d; box-shadow: none; }
      input, .secondary { background: #0d1117; color: #e6edf3; border-color: #30363d; }
    }
  </style>
</head>
<body><main>${body}</main></body>
</html>`;
}

function normalizeUserCode(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function formatUserCode(value: string): string {
  return `${value.slice(0, 4)}-${value.slice(4)}`;
}

function generateUserCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  for (let attempt = 0; attempt < 20; attempt += 1) {
    let code = "";
    for (let i = 0; i < 8; i += 1) {
      code += alphabet[randomBytes(1)[0] % alphabet.length];
    }
    if (!deviceCodesByUserCode.has(code)) return code;
  }
  return randomBytes(6).toString("hex").toUpperCase();
}

function getDeviceAuthorizationByUserCode(userCode: string): DeviceAuthorization | null {
  const normalized = normalizeUserCode(userCode);
  const deviceCode = deviceCodesByUserCode.get(normalized);
  if (!deviceCode) return null;

  const authorization = deviceAuthorizations.get(deviceCode);
  if (!authorization) {
    deviceCodesByUserCode.delete(normalized);
    return null;
  }

  if (authorization.exp < Date.now()) {
    deviceAuthorizations.delete(deviceCode);
    deviceCodesByUserCode.delete(normalized);
    return null;
  }

  return authorization;
}

function consumeDeviceOAuthState(state: string): DeviceAuthorization | null {
  const deviceCode = pendingDeviceOAuthStates.get(state);
  if (!deviceCode) return null;

  const authorization = deviceAuthorizations.get(deviceCode);
  if (!authorization || authorization.exp < Date.now()) {
    pendingDeviceOAuthStates.delete(state);
    if (authorization) {
      deviceAuthorizations.delete(deviceCode);
      deviceCodesByUserCode.delete(authorization.user_code);
    }
    return null;
  }

  return authorization;
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
    grant_types?: string[];
    response_types?: string[];
  };

  const grantTypes = Array.isArray(body.grant_types) && body.grant_types.length > 0
    ? body.grant_types
    : ["authorization_code", DEVICE_CODE_GRANT, "refresh_token"];
  const responseTypes = Array.isArray(body.response_types) && body.response_types.length > 0
    ? body.response_types
    : grantTypes.includes("authorization_code")
      ? ["code"]
      : [];
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];

  if (grantTypes.includes("authorization_code") && redirectUris.length === 0) {
    res.status(400).json({ error: "invalid_client_metadata", error_description: "redirect_uris is required" });
    return;
  }

  const isPublic = body.token_endpoint_auth_method === "none";
  const clientSecret = isPublic ? undefined : randomBytes(32).toString("hex");
  const issuedAt = Math.floor(Date.now() / 1000);
  const secretExpiresAt = isPublic ? undefined : issuedAt + 30 * 24 * 60 * 60;
  const clientId = createSignedClientId({
    typ: "client",
    jti: randomBytes(16).toString("hex"),
    client_secret_hash: clientSecret ? hashClientSecret(clientSecret) : undefined,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: body.token_endpoint_auth_method || (isPublic ? "none" : "client_secret_post"),
    client_name: body.client_name,
    scope: body.scope,
    grant_types: grantTypes,
    response_types: responseTypes,
    client_id_issued_at: issuedAt,
    client_secret_expires_at: secretExpiresAt,
  });
  const client: OAuthClient = {
    client_id: clientId,
    client_secret: clientSecret,
    client_secret_hash: clientSecret ? hashClientSecret(clientSecret) : undefined,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: body.token_endpoint_auth_method || (isPublic ? "none" : "client_secret_post"),
    client_name: body.client_name,
    scope: body.scope,
    grant_types: grantTypes,
    response_types: responseTypes,
    client_id_issued_at: issuedAt,
    client_secret_expires_at: secretExpiresAt,
  };
  oauthClients.set(clientId, client);

  const { client_secret_hash: _clientSecretHash, ...clientResponse } = client;
  res.status(201).json(clientResponse);
});

app.get("/login", (_req: Request, res: Response) => {
  res
    .status(200)
    .type("html")
    .send(
      htmlPage(
        "Docs MCP Login",
        `<h1>Docs MCP Login</h1>
        <p>Use browser login for local MCP clients that can receive an OAuth callback. Use device login when a CLI, SSH session, CI job, or remote server shows you a device code.</p>
        <div class="row">
          <a href="/auth/google/login">Browser Login</a>
          <a class="secondary" href="/device">Device Login</a>
        </div>`
      )
    );
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

app.post("/device_authorization", express.urlencoded({ extended: false }), (req: Request, res: Response) => {
  const body = req.body as {
    client_id?: string;
    client_secret?: string;
    scope?: string;
    resource?: string;
  };

  const client = authenticateClient(body);
  if (!client) {
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  const deviceCode = randomBytes(32).toString("hex");
  const userCode = generateUserCode();
  const authorization: DeviceAuthorization = {
    client_id: client.client_id,
    device_code: deviceCode,
    user_code: userCode,
    scope: body.scope || client.scope || DEFAULT_SCOPE,
    resource: body.resource,
    status: "pending",
    exp: Date.now() + DEVICE_CODE_TTL_SECONDS * 1000,
    intervalSeconds: DEVICE_CODE_INTERVAL_SECONDS,
  };
  deviceAuthorizations.set(deviceCode, authorization);
  deviceCodesByUserCode.set(userCode, deviceCode);

  res.json({
    device_code: deviceCode,
    user_code: formatUserCode(userCode),
    verification_uri: `${BASE_URL}/device`,
    verification_uri_complete: `${BASE_URL}/device?user_code=${encodeURIComponent(formatUserCode(userCode))}`,
    expires_in: DEVICE_CODE_TTL_SECONDS,
    interval: DEVICE_CODE_INTERVAL_SECONDS,
  });
});

app.get("/device", (req: Request, res: Response) => {
  const userCode = req.query.user_code ? formatUserCode(normalizeUserCode(String(req.query.user_code))) : "";
  res
    .status(200)
    .type("html")
    .send(
      htmlPage(
        "Device Login",
        `<h1>Device Login</h1>
        <p>Enter the device code shown by your MCP client or CLI.</p>
        <form method="post" action="/device">
          <input name="user_code" value="${userCode}" autocomplete="one-time-code" autofocus required>
          <div class="row"><button type="submit">Continue with Google</button></div>
        </form>`
      )
    );
});

app.post("/device", express.urlencoded({ extended: false }), (req: Request, res: Response) => {
  if (!requireOAuthConfig(res)) return;

  const body = req.body as { user_code?: string };
  const authorization = getDeviceAuthorizationByUserCode(String(body.user_code || ""));
  if (!authorization) {
    res
      .status(400)
      .type("html")
      .send(
        htmlPage(
          "Invalid Device Code",
          `<h1>Invalid Device Code</h1>
          <p>The code was not found or has expired.</p>
          <div class="row"><a href="/device">Try Again</a></div>`
        )
      );
    return;
  }

  const state = randomBytes(24).toString("hex");
  pendingDeviceOAuthStates.set(state, authorization.device_code);
  setCookie(res, STATE_COOKIE, state, DEVICE_CODE_TTL_SECONDS);

  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", GOOGLE_CLIENT_ID);
  url.searchParams.set("redirect_uri", OAUTH_REDIRECT_URI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", DEFAULT_SCOPE);
  url.searchParams.set("state", state);
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

  const client = getOAuthClient(clientId);
  if (!client || !client.redirect_uris.includes(redirectUri) || responseType !== "code") {
    if (redirectUri) redirectWithOAuthError(res, redirectUri, "invalid_request", state);
    else res.status(400).json({ error: "invalid_request" });
    return;
  }

  if (!codeChallenge || codeChallengeMethod !== "S256") {
    redirectWithOAuthError(res, redirectUri, "invalid_request", state);
    return;
  }

  const oauthState = randomBytes(24).toString("hex");
  pendingOAuthStates.set(oauthState, {
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    scope: req.query.scope ? String(req.query.scope) : client.scope || DEFAULT_SCOPE,
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

  const pendingDevice = consumeDeviceOAuthState(state);
  if (pendingDevice) {
    pendingDeviceOAuthStates.delete(state);
    pendingDevice.email = email;
    pendingDevice.status = "approved";
    res
      .status(200)
      .type("html")
      .send(
        htmlPage(
          "Device Login Approved",
          `<h1>Device Login Approved</h1>
          <p>You can return to your MCP client or CLI now.</p>`
        )
      );
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
    device_code?: string;
    refresh_token?: string;
  };

  if (body.grant_type === "refresh_token") {
    if (!body.refresh_token) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    const refreshToken = readOAuthToken(body.refresh_token, "refresh");
    if (!refreshToken) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    if (body.client_id && body.client_id !== refreshToken.client_id) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    const client = getOAuthClient(refreshToken.client_id);
    if (client?.client_secret && client.client_secret !== body.client_secret) {
      res.status(401).json({ error: "invalid_client" });
      return;
    }

    if (client?.client_secret && refreshToken.client_secret_hash !== clientSecretHash(client)) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    res.json(issueTokenResponseFromPayload({
      email: refreshToken.email,
      client_id: refreshToken.client_id,
      scope: refreshToken.scope,
      client_secret_hash: refreshToken.client_secret_hash,
    }));
    return;
  }

  const client = authenticateClient(body);
  if (!client) {
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  if (body.grant_type === "authorization_code") {
    if (!body.code) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    const authCode = authorizationCodes.get(body.code);
    if (!authCode || authCode.exp < Date.now() || authCode.client_id !== client.client_id) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    if (authCode.redirect_uri !== body.redirect_uri) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    if (authCode.code_challenge) {
      if (!body.code_verifier || !verifyPkce(body.code_verifier, authCode.code_challenge, authCode.code_challenge_method)) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }
    }

    authorizationCodes.delete(body.code);
    res.json(issueTokenResponse(client, authCode.email, authCode.scope || client.scope || DEFAULT_SCOPE));
    return;
  }

  if (body.grant_type === DEVICE_CODE_GRANT) {
    if (!body.device_code) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    const authorization = deviceAuthorizations.get(body.device_code);
    if (!authorization || authorization.exp < Date.now() || authorization.client_id !== client.client_id) {
      if (authorization) {
        deviceAuthorizations.delete(body.device_code);
        deviceCodesByUserCode.delete(authorization.user_code);
      }
      res.status(400).json({ error: "expired_token" });
      return;
    }

    const now = Date.now();
    if (authorization.lastPollAt && now - authorization.lastPollAt < authorization.intervalSeconds * 1000) {
      authorization.intervalSeconds += DEVICE_CODE_INTERVAL_SECONDS;
      res.status(400).json({ error: "slow_down", interval: authorization.intervalSeconds });
      return;
    }
    authorization.lastPollAt = now;

    if (authorization.status === "denied") {
      deviceAuthorizations.delete(authorization.device_code);
      deviceCodesByUserCode.delete(authorization.user_code);
      res.status(400).json({ error: "access_denied" });
      return;
    }

    if (authorization.status !== "approved" || !authorization.email) {
      res.status(400).json({ error: "authorization_pending" });
      return;
    }

    deviceAuthorizations.delete(authorization.device_code);
    deviceCodesByUserCode.delete(authorization.user_code);
    res.json(issueTokenResponse(client, authorization.email, authorization.scope || client.scope || DEFAULT_SCOPE));
    return;
  }

  if (!body.grant_type) {
    res.status(400).json({ error: "invalid_request" });
    return;
  }
  res.status(400).json({ error: "unsupported_grant_type" });
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
