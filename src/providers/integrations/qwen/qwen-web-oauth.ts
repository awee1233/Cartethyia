/**
 * Qwen Web — OAuth token refresher.
 *
 * Qwen Chat's access token lives roughly fifteen minutes, so a stored token is
 * almost always stale by the time a request arrives. The refresh grant is a
 * plain POST to the auth host carrying only the refresh token:
 *
 *   POST https://auth.qwen.ai/api/v2/auths/refresh  {"refresh_token": …}
 *   -> {"success": true, "data": {"access_token": …, "refresh_token": …}}
 *
 * Two properties of that endpoint shape this client:
 *
 *  - The auth surface expects `source: web`, not the `qwen_app` identity the
 *    chat surface wants. Sending the wrong one is answered with
 *    `Invalid request header` rather than an auth failure, which is easy to
 *    misread as a dead credential.
 *  - Refresh tokens ROTATE and are single-use: every successful refresh returns
 *    a new one, and reusing the previous value is answered with
 *    `Token is revoked`. The result therefore always carries the replacement.
 *
 * `Too_Many_Requests` is a throttle, not a rejection. It is surfaced as a
 * retryable refresh failure so the shared worker backs off instead of retiring
 * an account that is still perfectly usable.
 */
import { GatewayError } from "../../../protocol/gateway-error";
import { truncateUpstreamText } from "../../authentication/oauth-flow-store";
import type {
  OAuthExchangeResult,
  OAuthImportInput,
  OAuthLoginClient,
  OAuthLoginField,
} from "../../authentication/oauth-flow-store";
import type { OAuthTokenRefreshResult } from "../../authentication/oauth-refresh-service";
import type { FetchLike } from "../../authentication/oauth-client";

export const QWEN_AUTH_REFRESH_URL = "https://auth.qwen.ai/api/v2/auths/refresh";
export const QWEN_CLIENT_VERSION = "0.3.12";
export const QWEN_REFRESH_TIMEOUT_MS = 20_000;

/** Milliseconds of slack subtracted from a reported expiry. */
const EXPIRY_SKEW_MS = 60_000;
/**
 * Lifetime assumed when the upstream reports no expiry. Qwen's access tokens
 * last about fifteen minutes; treating a fresh one as an hour would let it go
 * stale mid-flight, so the conservative value is used instead.
 */
const ASSUMED_LIFETIME_MS = 10 * 60_000;

interface QwenRefreshPayload {
  readonly success?: unknown;
  readonly data?: {
    readonly access_token?: unknown;
    readonly refresh_token?: unknown;
    readonly expires_in?: unknown;
    readonly code?: unknown;
    readonly details?: unknown;
  };
}

/** Auth-surface headers. `source: web` is required; `qwen_app` is rejected. */
function authHeaders(): Record<string, string> {
  return {
    accept: "application/json",
    "content-type": "application/json",
    "accept-language": "en-US,en;q=0.9",
    version: QWEN_CLIENT_VERSION,
    source: "web",
    "x-request-id": String(Date.now()),
    "x-request-origin": "https://chat.qwen.ai",
    origin: "https://chat.qwen.ai",
  };
}

export interface QwenWebOAuthOptions {
  readonly fetch?: FetchLike;
  readonly refreshUrl?: string;
}

class QwenWebOAuthRefresher implements OAuthLoginClient {
  private readonly fetchFn: FetchLike;
  private readonly refreshUrl: string;

  /** Import-only client: there is no interactive authorize or device flow. */
  readonly supportsDeviceCode = false;
  readonly supportsBrowserCode = false;

  /**
   * The operator pastes what the web app shows. Two values are needed because
   * the access token alone cannot outlive its fifteen minutes — without the
   * refresh token the account would work once and then go dark.
   */
  readonly importFields: readonly OAuthLoginField[] = [
    {
      key: "refreshToken",
      label: "Refresh token (chat.qwen.ai → Local Storage → token)",
      required: true,
      secret: true,
      placeholder: "eyJhbGciOi…",
    },
  ];

  constructor(options: QwenWebOAuthOptions = {}) {
    this.fetchFn = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
    this.refreshUrl = options.refreshUrl ?? QWEN_AUTH_REFRESH_URL;
  }

  /**
   * Accepts the pasted credential, mints a usable access token from it, and
   * hands both back for persistence.
   *
   * The refresh token is validated by actually using it: a refresh grant is
   * the only upstream call that proves the token is live, and a stored
   * credential that fails here would otherwise be discovered at dispatch time.
   */
  async importCredential(input: OAuthImportInput): Promise<OAuthExchangeResult> {
    const refreshToken = resolveRefreshToken(input);
    if (refreshToken.length === 0) {
      throw new Error(
        "Paste a Qwen refresh token (or a JSON blob carrying accessToken and refreshToken)",
      );
    }

    const refreshed = await this.refresh(refreshToken);
    return {
      access: refreshed.access,
      // Always present on this provider: the grant rotates the token.
      refresh: refreshed.refresh ?? refreshToken,
      expiresAt: refreshed.expiresAt,
      ...(input.accountLabel ? { accountLabel: input.accountLabel } : {}),
    };
  }

  async refresh(
    refreshToken: string,
    signal?: AbortSignal,
  ): Promise<OAuthTokenRefreshResult> {
    if (refreshToken.trim().length === 0) {
      throw new GatewayError(
        "authentication_failed",
        401,
        "qwen-web: refresh token is empty; sign in again",
      );
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), QWEN_REFRESH_TIMEOUT_MS);
    const composed = composeSignal(signal, controller.signal);

    let response: Response;
    try {
      response = await this.fetchFn(this.refreshUrl, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ refresh_token: refreshToken }),
        signal: composed,
      });
    } catch (error) {
      // A transport failure says nothing about the credential, so it is
      // retryable rather than terminal.
      throw new GatewayError(
        "transport_unavailable",
        503,
        `qwen-web: refresh transport failed (${error instanceof Error ? error.message : "unknown"})`,
      );
    } finally {
      clearTimeout(timeout);
    }

    const text = await response.text();
    const payload = parse(text);

    if (payload?.success === true) {
      const access = payload.data?.access_token;
      if (typeof access !== "string" || access.length === 0) {
        throw new GatewayError(
          "platform_unavailable",
          502,
          "qwen-web: refresh succeeded without an access token",
        );
      }
      const rotated = payload.data?.refresh_token;
      const expiresIn = payload.data?.expires_in;
      return {
        access,
        // Rotation is the norm here; keep the previous value only when the
        // upstream truly sent none.
        refresh: typeof rotated === "string" && rotated.length > 0 ? rotated : refreshToken,
        expiresAt: expiryFrom(expiresIn),
      };
    }

    const code = String(payload?.data?.code ?? "");
    const details = String(payload?.data?.details ?? "");
    const blob = `${code} ${details}`.toLowerCase();

    if (blob.includes("too_many") || blob.includes("too many")) {
      // Back off rather than retire: the token is still valid.
      throw new GatewayError(
        "accounts_rate_limited",
        429,
        `qwen-web: refresh throttled (${truncateUpstreamText(details || code, 120)})`,
      );
    }
    if (blob.includes("revoked")) {
      throw new GatewayError(
        "authentication_failed",
        401,
        "qwen-web: refresh token was already used or revoked; sign in again",
      );
    }
    if (blob.includes("expired")) {
      throw new GatewayError(
        "authentication_failed",
        401,
        "qwen-web: refresh token expired; sign in again",
      );
    }
    throw new GatewayError(
      "authentication_failed",
      response.status === 200 ? 401 : response.status,
      `qwen-web: refresh rejected (${truncateUpstreamText(
        details || code || `HTTP ${response.status}`, 160)})`,
    );
  }
}

/**
 * Pulls the refresh token out of the pasted credential.
 *
 * Two shapes are accepted because both are natural to paste: the bare refresh
 * token string, and a JSON blob carrying `accessToken`/`refreshToken` (what a
 * scanner or an exported session produces). A bare access token is not
 * accepted — it would work for fifteen minutes and then silently fail.
 */
function resolveRefreshToken(input: OAuthImportInput): string {
  const raw = input.credential.trim();
  if (raw.length === 0) return "";

  const fromField = (input.fields["refreshToken"] ?? "").trim();
  if (fromField.length > 0) return fromField;

  if (!raw.startsWith("{")) return raw;

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    for (const key of ["refresh_token", "refreshToken"]) {
      const value = parsed[key];
      if (typeof value === "string" && value.trim().length > 0) {
        return value.trim();
      }
    }
  } catch {
    return "";
  }
  return "";
}

/** Expiry for a refresh that either reported a lifetime or did not. */
function expiryFrom(expiresIn: unknown): Date {
  const seconds = typeof expiresIn === "number" ? expiresIn : Number(expiresIn);
  const lifetime = Number.isFinite(seconds) && seconds > 0
    ? seconds * 1000
    : ASSUMED_LIFETIME_MS;
  return new Date(Date.now() + Math.max(lifetime - EXPIRY_SKEW_MS, 1000));
}

function parse(text: string): QwenRefreshPayload | null {
  try {
    const parsed = JSON.parse(text);
    return parsed !== null && typeof parsed === "object"
      ? (parsed as QwenRefreshPayload)
      : null;
  } catch {
    return null;
  }
}

/** Merges the caller's signal with the internal timeout signal. */
function composeSignal(
  outer: AbortSignal | undefined,
  inner: AbortSignal,
): AbortSignal {
  if (outer === undefined) return inner;
  if (typeof AbortSignal.any === "function") {
    return AbortSignal.any([outer, inner]);
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (outer.aborted || inner.aborted) controller.abort();
  outer.addEventListener("abort", abort, { once: true });
  inner.addEventListener("abort", abort, { once: true });
  return controller.signal;
}

/**
 * The refresher is also the login client contract's `refresh` member, so the
 * same object satisfies both capability loaders.
 */
export function createQwenWebOAuth(options: QwenWebOAuthOptions = {}) {
  return new QwenWebOAuthRefresher(options);
}

export const qwenWebOAuthClient = createQwenWebOAuth();
