import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { expandHomePath } from "./roots.js";
import type { LoggingConfig, LogFormat, LogLevel } from "./logger.js";
import type { OAuthConfig } from "./oauth-provider.js";
import { loadDevspaceFiles } from "./user-config.js";

export type ToolMode = "minimal" | "full" | "codex";
export type WidgetMode = "off" | "changes" | "full";
const DEFAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const DEFAULT_OAUTH_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

export interface ServerConfig {
  host: string;
  port: number;
  oauth: OAuthConfig;
  allowedRoots: string[];
  allowedHosts: string[];
  publicBaseUrl: string;
  toolMode: ToolMode;
  widgets: WidgetMode;
  stateDir: string;
  worktreeRoot: string;
  skillsEnabled: boolean;
  skillPaths: string[];
  agentDir: string;
  logging: LoggingConfig;
  /**
   * Express `trust proxy` hop count. `undefined` defers to the upstream
   * `DEVSPACE_TRUST_PROXY` boolean so the original behavior is preserved when
   * the hops gate is not set.
   */
  trustProxyHops: number | undefined;
}

/**
 * Whether request logging should read forwarded headers (cf-connecting-ip /
 * x-forwarded-for). When the hops gate is set it is authoritative; otherwise
 * the upstream `DEVSPACE_TRUST_PROXY` boolean decides, matching upstream.
 */
export function trustForwardedHeaders(config: ServerConfig): boolean {
  if (config.trustProxyHops !== undefined) return config.trustProxyHops > 0;
  return config.logging.trustProxy;
}

/** Short human-readable trust-proxy state for startup banners. */
export function describeTrustProxy(config: ServerConfig): string {
  // Gate-unset path mirrors the exact upstream banner strings ("enabled"/"disabled")
  // so the upstream startup output is reproducible byte-for-byte.
  if (config.trustProxyHops === undefined) {
    return config.logging.trustProxy ? "enabled" : "disabled";
  }
  return config.trustProxyHops > 0
    ? `enabled (hops=${config.trustProxyHops})`
    : "disabled (hops=0)";
}

function parsePort(value: string | number | undefined): number {
  if (value === undefined || value === "") return 7676;

  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PORT: ${value}`);
  }

  return port;
}

function parseAllowedRoots(value: string | string[] | undefined): string[] {
  if (Array.isArray(value)) {
    const roots = value.map((entry) => entry.trim()).filter(Boolean);
    return (roots.length > 0 ? roots : [process.cwd()]).map((root) => resolve(expandHomePath(root)));
  }

  const rawRoots =
    value
      ?.split(",")
      .map((entry) => entry.trim())
      .filter(Boolean) ?? [];

  const roots = rawRoots.length > 0 ? rawRoots : [process.cwd()];
  return roots.map((root) => resolve(expandHomePath(root)));
}

function parseAllowedHosts(value: string | string[] | undefined, derivedHosts: string[]): string[] {
  if (Array.isArray(value)) {
    return normalizeAllowedHosts(value, derivedHosts);
  }

  const rawHosts =
    value
      ?.split(",")
      .map((entry) => entry.trim())
      .filter(Boolean) ?? [];

  return normalizeAllowedHosts(rawHosts, derivedHosts);
}

function normalizeAllowedHosts(rawHosts: string[], derivedHosts: string[]): string[] {
  const hosts = rawHosts.length > 0 ? rawHosts : derivedHosts;
  if (hosts.includes("*")) return ["*"];
  return Array.from(new Set(hosts.map((host) => host.trim()).filter(Boolean)));
}

function parseBoolean(value: string | undefined): boolean {
  return ["1", "true", "yes", "on"].includes(value?.toLowerCase() ?? "");
}

/** Raw value of `DEVSPACE_TRUST_PROXY_HOPS`: undefined (gate unset), "auto", or a hop count. */
function parseTrustProxyHopsRaw(value: string | undefined): undefined | "auto" | number {
  if (value === undefined || value === "") return undefined;
  if (value.toLowerCase() === "auto") return "auto";
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`Invalid DEVSPACE_TRUST_PROXY_HOPS: ${value}. Use "auto" or a non-negative integer.`);
  }
  return parsed;
}

// 0.0.0.0 is treated as loopback to match localPublicBaseUrl, which maps the
// unspecified bind address to 127.0.0.1 for the derived default public URL.
function isLoopbackHost(hostname: string): boolean {
  return ["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"].includes(hostname);
}

/** Resolves "auto" to a concrete hop count: one proxy behind a tunnel, none on loopback. */
function resolveTrustProxyHops(
  raw: undefined | "auto" | number,
  publicBaseUrl: string,
): number | undefined {
  if (raw === undefined) return undefined;
  if (raw === "auto") return isLoopbackHost(new URL(publicBaseUrl).hostname) ? 0 : 1;
  return raw;
}

function parseToolMode(env: NodeJS.ProcessEnv): ToolMode {
  const mode = env.DEVSPACE_TOOL_MODE;
  if (mode === "minimal" || mode === "full" || mode === "codex") return mode;
  if (mode) throw new Error(`Invalid DEVSPACE_TOOL_MODE: ${mode}`);

  if (env.DEVSPACE_MINIMAL_TOOLS !== undefined) {
    return parseBoolean(env.DEVSPACE_MINIMAL_TOOLS) ? "minimal" : "full";
  }
  return "minimal";
}

function parseLogLevel(value: string | undefined): LogLevel {
  if (!value || value === "info") return "info";
  if (["silent", "error", "warn", "debug"].includes(value)) return value as LogLevel;

  throw new Error(`Invalid DEVSPACE_LOG_LEVEL: ${value}`);
}

function parseLogFormat(value: string | undefined): LogFormat {
  if (!value || value === "json") return "json";
  if (value === "pretty") return "pretty";

  throw new Error(`Invalid DEVSPACE_LOG_FORMAT: ${value}`);
}

function parsePathList(value: string | undefined): string[] {
  return (
    value
      ?.split(",")
      .map((entry) => entry.trim())
      .filter(Boolean) ?? []
  );
}

function parseStringList(value: string | undefined, fallback: string[]): string[] {
  const entries = value
    ?.split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

  return entries && entries.length > 0 ? entries : fallback;
}

function parsePositiveInteger(value: string | undefined, fallback: number, name: string): number {
  if (!value) return fallback;

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`Invalid ${name}: ${value}`);
  }

  return parsed;
}

function parseLoggingConfig(env: NodeJS.ProcessEnv): LoggingConfig {
  return {
    level: parseLogLevel(env.DEVSPACE_LOG_LEVEL),
    format: parseLogFormat(env.DEVSPACE_LOG_FORMAT),
    requests: env.DEVSPACE_LOG_REQUESTS === undefined ? true : parseBoolean(env.DEVSPACE_LOG_REQUESTS),
    assets: parseBoolean(env.DEVSPACE_LOG_ASSETS),
    toolCalls: env.DEVSPACE_LOG_TOOL_CALLS === undefined ? true : parseBoolean(env.DEVSPACE_LOG_TOOL_CALLS),
    shellCommands: parseBoolean(env.DEVSPACE_LOG_SHELL_COMMANDS),
    trustProxy: parseBoolean(env.DEVSPACE_TRUST_PROXY),
  };
}

function parseWidgetMode(value: string | undefined): WidgetMode {
  if (!value || value === "full") return "full";
  if (value === "off" || value === "changes") return value;

  throw new Error(`Invalid DEVSPACE_WIDGETS: ${value}`);
}

function parseRequiredSecret(value: string | undefined, name: string): string {
  const secret = value?.trim();
  if (!secret) {
    throw new Error(`${name} is required for DevSpace OAuth. Run: devspace init`);
  }
  if (secret.length < 16) {
    throw new Error(`${name} must be at least 16 characters long.`);
  }
  return secret;
}

function parseOAuthConfig(env: NodeJS.ProcessEnv, ownerToken: string | undefined): OAuthConfig {
  return {
    ownerToken: parseRequiredSecret(env.DEVSPACE_OAUTH_OWNER_TOKEN ?? ownerToken, "DEVSPACE_OAUTH_OWNER_TOKEN"),
    accessTokenTtlSeconds: parsePositiveInteger(
      env.DEVSPACE_OAUTH_ACCESS_TOKEN_TTL_SECONDS,
      DEFAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS,
      "DEVSPACE_OAUTH_ACCESS_TOKEN_TTL_SECONDS",
    ),
    refreshTokenTtlSeconds: parsePositiveInteger(
      env.DEVSPACE_OAUTH_REFRESH_TOKEN_TTL_SECONDS,
      DEFAULT_OAUTH_REFRESH_TOKEN_TTL_SECONDS,
      "DEVSPACE_OAUTH_REFRESH_TOKEN_TTL_SECONDS",
    ),
    scopes: parseStringList(env.DEVSPACE_OAUTH_SCOPES, ["devspace"]),
    allowedRedirectHosts: parseStringList(env.DEVSPACE_OAUTH_ALLOWED_REDIRECT_HOSTS, [
      "chatgpt.com",
      "localhost",
      "127.0.0.1",
    ]),
  };
}

function defaultStateDir(): string {
  return join(homedir(), ".local", "share", "devspace");
}

function defaultWorktreeRoot(): string {
  return join(homedir(), ".devspace", "worktrees");
}

function defaultAgentDir(): string {
  return join(homedir(), ".codex");
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const files = loadDevspaceFiles(env);
  const host = env.HOST ?? files.config.host ?? "127.0.0.1";
  const port = parsePort(env.PORT ?? files.config.port);
  const publicBaseUrl = parsePublicBaseUrl(
    env.DEVSPACE_PUBLIC_BASE_URL ?? files.config.publicBaseUrl ?? localPublicBaseUrl(host, port),
  );
  const derivedAllowedHosts = [
    "localhost",
    "127.0.0.1",
    "::1",
    host,
    new URL(publicBaseUrl).hostname,
    ...(files.config.allowedHosts ?? []),
  ];

  return {
    host,
    port,
    oauth: parseOAuthConfig(env, files.auth.ownerToken),
    allowedRoots: parseAllowedRoots(env.DEVSPACE_ALLOWED_ROOTS ?? files.config.allowedRoots),
    allowedHosts: parseAllowedHosts(env.DEVSPACE_ALLOWED_HOSTS, derivedAllowedHosts),
    publicBaseUrl,
    toolMode: parseToolMode(env),
    widgets: parseWidgetMode(env.DEVSPACE_WIDGETS),
    stateDir: resolve(expandHomePath(env.DEVSPACE_STATE_DIR ?? files.config.stateDir ?? defaultStateDir())),
    worktreeRoot: resolve(expandHomePath(env.DEVSPACE_WORKTREE_ROOT ?? files.config.worktreeRoot ?? defaultWorktreeRoot())),
    skillsEnabled: env.DEVSPACE_SKILLS === undefined ? true : parseBoolean(env.DEVSPACE_SKILLS),
    skillPaths: parsePathList(env.DEVSPACE_SKILL_PATHS),
    agentDir: resolve(expandHomePath(env.DEVSPACE_AGENT_DIR ?? files.config.agentDir ?? defaultAgentDir())),
    logging: parseLoggingConfig(env),
    trustProxyHops: resolveTrustProxyHops(
      parseTrustProxyHopsRaw(env.DEVSPACE_TRUST_PROXY_HOPS),
      publicBaseUrl,
    ),
  };
}

function parsePublicBaseUrl(value: string): string {
  const parsed = new URL(value);
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/$/, "");
}

function localPublicBaseUrl(host: string, port: number): string {
  const publicHost = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const formattedHost = publicHost.includes(":") && !publicHost.startsWith("[")
    ? `[${publicHost}]`
    : publicHost;
  return `http://${formattedHost}:${port}`;
}
