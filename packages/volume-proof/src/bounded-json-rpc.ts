export const MAX_JSON_RPC_RESPONSE_BYTES = 256 * 1_024;

export interface JsonRpcResponse<T> {
  result?: T;
  error?: { code?: number; message?: string };
}

async function cancelBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The caller receives the original bounded-read error.
  }
}

export async function readBoundedJsonRpcResponse<T>(
  response: Response,
  maxBytes = MAX_JSON_RPC_RESPONSE_BYTES,
): Promise<JsonRpcResponse<T>> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error("RPC_RESPONSE_LIMIT_INVALID");
  }
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d+$/.test(declared) || Number(declared) > maxBytes) {
      await cancelBody(response);
      throw new Error("RPC_RESPONSE_TOO_LARGE");
    }
  }
  if (!response.body) throw new Error("RPC_RESPONSE_BODY_MISSING");

  const reader = response.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error("RPC_RESPONSE_TOO_LARGE");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("RPC_RESPONSE_JSON_INVALID");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("RPC_RESPONSE_ENVELOPE_INVALID");
  }
  return parsed as JsonRpcResponse<T>;
}
