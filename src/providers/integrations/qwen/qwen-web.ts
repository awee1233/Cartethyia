/**
 * Qwen Web (chat.qwen.ai) — web-session adapter.
 *
 * Qwen Chat's web surface is not OpenAI-compatible: one turn is two calls and
 * a fixed set of browser-identity headers.
 *
 *   1. `POST /api/v2/chats/new` mints the `chat_id` for the conversation.
 *   2. `POST /api/v2/chat/completions?chat_id=<id>` streams the answer as SSE
 *      whose frames already carry OpenAI-shaped `choices[].delta.content`.
 *
 * The WAF answers a bare request with an HTML "punish" page, so every
 * completion call repeats `source: qwen_app` with the published `app_waf`
 * value and the client `Version` the web bundle reports. The chat-minting call
 * uses `source: web` without `app_waf` — the same split the web client makes.
 *
 * Credential: the bearer token copied from the web app. An `oauth` credential
 * whose secret is a `{"accessToken": …}` envelope is unwrapped here, so the
 * standard refresh path can rotate the token without operator involvement.
 */
import type {
  CanonicalEvent,
  CanonicalRequest,
} from "../../../protocol/canonical-model";
import { GatewayError } from "../../../protocol/gateway-error";
import { usageFromProvider } from "../../usage";
import { defineModel } from "../../model-definition";
import type { ModelDefinition } from "../../model-definition";
import type {
  ProviderAdapter,
  ProviderDispatchContext,
  ProviderDispatchTarget,
} from "../../contracts";
import { providerBaseUrl } from "../../metadata";

export const QWEN_WEB_PROVIDER_ID = "qwen-web" as const;

/** Root URL — the chat API is rooted at `/api`, not a `/v1` segment. */
export const QWEN_WEB_BASE_URL = providerBaseUrl("qwen-web");

/** Published WAF token the web client repeats on completion calls. */
const QWEN_APP_WAF = "Z9Tr56YmQpXcO2K_d_3nAbJvRqMLFW8HTNjvRguWHEowM1xY";

/** Client build the web bundle reports; the WAF checks it. */
const QWEN_CLIENT_VERSION = "0.3.12";

/** Browser identity the web client presents to its own backend. */
const QWEN_ORIGIN = "https://chat.qwen.ai";

const qwenModel = (
  modelId: string,
  contextLimit: number,
  outputLimit: number,
  vision: boolean,
): ModelDefinition =>
  defineModel({
    id: modelId,
    providerId: QWEN_WEB_PROVIDER_ID,
    wireFamily: "chat",
    endpoint: "/api/v2/chat/completions",
    ctx: contextLimit,
    out: outputLimit,
    vision,
    reasoning: true,
    toolCall: false,
  });

export const QWEN_WEB_MODELS: readonly ModelDefinition[] = [
  qwenModel("qwen3.8-max-preview", 1_000_000, 65_536, true),
  qwenModel("qwen3.7-max", 1_000_000, 65_536, false),
  qwenModel("qwen3.7-plus", 1_000_000, 65_536, true),
  qwenModel("qwen3.6-plus", 1_000_000, 65_536, true),
];

/** Identity headers both calls share; only two keys differ between them. */
function qwenHeaders(token: string, streaming: boolean): Record<string, string> {
  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
    accept: streaming ? "text/event-stream" : "application/json, text/plain, */*",
    "content-type": streaming
      ? "application/json; charset=UTF-8"
      : "application/json",
    "accept-language": "en-US,en;q=0.9",
    origin: QWEN_ORIGIN,
    referer: `${QWEN_ORIGIN}/`,
    version: QWEN_CLIENT_VERSION,
    source: streaming ? "qwen_app" : "web",
    "x-request-id": String(Date.now()),
    "x-request-origin": QWEN_ORIGIN,
    timezone: new Date().toUTCString(),
    "user-agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  };
  if (streaming) headers.app_waf = QWEN_APP_WAF;
  return headers;
}

interface QwenWebAdapterOptions {
  readonly fetch?: typeof fetch;
  readonly baseUrl?: string;
}

class QwenWebAdapter implements ProviderAdapter {
  readonly provider_id = QWEN_WEB_PROVIDER_ID;
  private readonly fetchFn: typeof fetch;
  private readonly baseUrl: string;

  constructor(options: QwenWebAdapterOptions = {}) {
    this.fetchFn = options.fetch ?? globalThis.fetch;
    this.baseUrl = (options.baseUrl ?? QWEN_WEB_BASE_URL).replace(/\/+$/, "");
  }

  dispatch(
    request: CanonicalRequest,
    candidate: ProviderDispatchTarget,
    context: ProviderDispatchContext,
  ): AsyncIterable<CanonicalEvent> {
    return this.dispatchRaw(request, candidate, context);
  }

  private async *dispatchRaw(
    request: CanonicalRequest,
    candidate: ProviderDispatchTarget,
    context: ProviderDispatchContext,
  ): AsyncIterable<CanonicalEvent> {
    const token = readBearerToken(context);
    const model = candidate.model_id || request.model;
    let seq = 0;

    const chatId = await this.createChat(token, context);
    const response = await this.complete(chatId, model, request, token, context);

    if (response.body === null) {
      throw new GatewayError(
        "transport_unavailable",
        502,
        "qwen-web: completion stream is missing",
      );
    }

    yield { type: "response_start", sequence_number: seq++, model };

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let terminal = false;
    let usage: { input: number; output: number } | null = null;

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.length === 0 || trimmed.startsWith(":")) continue;
          if (!trimmed.startsWith("data:")) continue;
          const payload = trimmed.slice(5).trim();
          if (payload === "[DONE]") {
            if (!terminal) {
              yield* finish(seq, usage);
              seq += terminalEvents(usage);
              terminal = true;
            }
            continue;
          }
          const chunk = safeJson(payload);
          if (chunk === null) continue;

          const text = firstDeltaText(chunk);
          if (text !== null && text.length > 0) {
            yield {
              type: "content_delta",
              sequence_number: seq++,
              content: { kind: "text", text },
            };
          }

          const counted = readUsage(chunk);
          if (counted !== null) usage = counted;
        }
      }
    } finally {
      await reader.cancel().catch(() => undefined);
    }

    if (!terminal) {
      yield* finish(seq, usage);
    }
  }

  /** Mints a conversation id; `source: web` (no WAF token) is the right identity. */
  private async createChat(
    token: string,
    context: ProviderDispatchContext,
  ): Promise<string> {
    const response = await this.fetchFn(`${this.baseUrl}/api/v2/chats/new`, {
      method: "POST",
      signal: context.abort_signal,
      headers: qwenHeaders(token, false),
      body: JSON.stringify({ chat_mode: "normal" }),
    });

    const parsed = await readJson(response);
    if (!response.ok || parsed?.success !== true) {
      throw new GatewayError(
        "transport_unavailable",
        response.status === 200 ? 502 : response.status,
        `qwen-web: could not open a chat (${describe(response.status, parsed)})`,
      );
    }

    const id = (parsed.data as { id?: unknown } | undefined)?.id;
    if (typeof id !== "string" || id.length === 0) {
      throw new GatewayError(
        "transport_unavailable",
        502,
        "qwen-web: chat creation returned no id",
      );
    }
    return id;
  }

  private async complete(
    chatId: string,
    model: string,
    request: CanonicalRequest,
    token: string,
    context: ProviderDispatchContext,
  ): Promise<Response> {
    const url =
      `${this.baseUrl}/api/v2/chat/completions?chat_id=${encodeURIComponent(chatId)}`;

    const response = await this.fetchFn(url, {
      method: "POST",
      signal: context.abort_signal,
      headers: qwenHeaders(token, true),
      body: JSON.stringify(completionBody(chatId, model, request)),
    });

    if (!response.ok) {
      const detail = (await response.text().catch(() => "")).slice(0, 200);
      throw new GatewayError(
        "transport_unavailable",
        response.status,
        `qwen-web: completion rejected with HTTP ${response.status}${detail ? `: ${detail}` : ""}`,
      );
    }
    return response;
  }
}

/** Emits the usage record (when reported) followed by the terminal event. */
function* finish(
  seq: number,
  usage: { input: number; output: number } | null,
): Generator<CanonicalEvent> {
  if (usage !== null) {
    // Route through the shared normalizer so the record carries every required
    // field (cache counters, cost) rather than only the two the web API sends.
    const record = usageFromProvider({
      input_tokens: usage.input,
      output_tokens: usage.output,
    });
    if (record !== undefined) {
      yield { type: "usage", sequence_number: seq++, usage: record };
    }
  }
  yield {
    type: "terminal",
    state: "complete",
    stop_reason: "stop",
    sequence_number: seq,
  };
}

/** Number of events `finish` will emit — keeps the caller's cursor honest. */
function terminalEvents(usage: { input: number; output: number } | null): number {
  return usage === null ? 1 : 2;
}

/**
 * Reads the bearer token from either credential kind.
 *
 * An `oauth` secret may be a JSON envelope rather than the bare token, because
 * the refresh path stores the token alongside its metadata. Both shapes are
 * accepted; anything else is a sign-in problem, not a dispatch failure.
 */
function readBearerToken(context: ProviderDispatchContext): string {
  const secret = context.credential.secret;
  if (secret === undefined || secret === null) {
    throw new GatewayError(
      "authentication_failed",
      401,
      "qwen-web: a bearer token is required; sign in again",
    );
  }
  const raw = new TextDecoder().decode(secret).trim();
  if (raw.length === 0) {
    throw new GatewayError(
      "authentication_failed",
      401,
      "qwen-web: credential is empty; sign in again",
    );
  }
  if (!raw.startsWith("{")) return raw;

  const parsed = safeJson(raw);
  const token = parsed?.accessToken ?? parsed?.access_token;
  if (typeof token === "string" && token.length > 0) return token;
  throw new GatewayError(
    "authentication_failed",
    401,
    "qwen-web: credential envelope carries no access token; sign in again",
  );
}

/** Builds the body the web app posts to `/api/v2/chat/completions`. */
function completionBody(
  chatId: string,
  model: string,
  request: CanonicalRequest,
): Record<string, unknown> {
  const messages = (request.messages ?? []).map((message) => ({
    role: message.role,
    content: flattenContent(message.content),
    chat_type: "t2t",
    feature_config: { thinking_enabled: false, output_schema: "phase" },
  }));

  return {
    stream: true,
    incremental_output: true,
    chat_id: chatId,
    chat_mode: "normal",
    model,
    messages,
    timestamp: Math.floor(Date.now() / 1000),
  };
}

/** Collapses canonical content parts into the plain string the web API takes. */
function flattenContent(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const part of content) {
    if (typeof part === "string") {
      parts.push(part);
      continue;
    }
    if (part !== null && typeof part === "object" && "text" in part) {
      const text = (part as { text?: unknown }).text;
      if (typeof text === "string") parts.push(text);
    }
  }
  return parts.join("");
}

/** Pulls `choices[0].delta.content` out of one upstream frame. */
function firstDeltaText(chunk: Record<string, unknown>): string | null {
  const choices = chunk.choices;
  if (!Array.isArray(choices) || choices.length === 0) return null;
  const delta = (choices[0] as { delta?: unknown } | undefined)?.delta;
  if (delta === null || typeof delta !== "object") return null;
  const content = (delta as { content?: unknown }).content;
  return typeof content === "string" ? content : null;
}

function readUsage(chunk: Record<string, unknown>): { input: number; output: number } | null {
  const usage = chunk.usage;
  if (usage === null || typeof usage !== "object") return null;
  const input = (usage as { input_tokens?: unknown }).input_tokens;
  const output = (usage as { output_tokens?: unknown }).output_tokens;
  if (typeof input !== "number" && typeof output !== "number") return null;
  return {
    input: typeof input === "number" ? input : 0,
    output: typeof output === "number" ? output : 0,
  };
}

async function readJson(response: Response): Promise<Record<string, unknown> | null> {
  try {
    const parsed = await response.json();
    return parsed !== null && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function safeJson(text: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(text);
    return parsed !== null && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Surfaces the upstream's own reason when it supplies one. */
function describe(status: number, body: Record<string, unknown> | null): string {
  const details = (body?.data as { details?: unknown } | undefined)?.details;
  if (typeof details === "string" && details.length > 0) {
    return `HTTP ${status}: ${details}`;
  }
  return `HTTP ${status}`;
}

export function createQwenWebAdapter(
  options: QwenWebAdapterOptions = {},
): ProviderAdapter {
  return new QwenWebAdapter(options);
}

export const qwenWebAdapter: ProviderAdapter = createQwenWebAdapter();
