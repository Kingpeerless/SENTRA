export const ACCESS_TOKEN_EXPIRED_EVENT = "sentra:access-token-expired";

let accessToken: string | null = null;

export function setAccessToken(token: string): void {
  if (token.length === 0) throw new Error("An access token is required.");
  accessToken = token;
}

export function clearAccessToken(): void {
  accessToken = null;
}

export async function verifyAccessToken(
  token: string,
  fetchImplementation: typeof fetch = fetch,
): Promise<boolean> {
  if (token.length === 0) return false;
  const response = await fetchImplementation("/api/auth/verify", {
    method: "GET",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
    },
    cache: "no-store",
  });
  if (response.status === 401) return false;
  if (!response.ok) {
    throw new Error("SENTRA could not verify the access token.");
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("SENTRA returned an invalid access verification response.");
  }
  return typeof payload === "object" &&
    payload !== null &&
    "data" in payload &&
    typeof payload.data === "object" &&
    payload.data !== null &&
    "authenticated" in payload.data &&
    payload.data.authenticated === true;
}

export async function authenticatedApiFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
  fetchImplementation: typeof fetch = fetch,
): Promise<Response> {
  if (!accessToken) throw new Error("SENTRA access session is unavailable.");
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${accessToken}`);
  const response = await fetchImplementation(input, { ...init, headers });
  if (response.status === 401 && typeof window !== "undefined") {
    window.dispatchEvent(new Event(ACCESS_TOKEN_EXPIRED_EVENT));
  }
  return response;
}
