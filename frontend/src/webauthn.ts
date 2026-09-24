/** Minimal WebAuthn client helpers — no external dependency.

The ceremony is fully server-driven: the backend issues
PublicKeyCredentialCreationOptions, we decode the base64url fields
the browser needs as ArrayBuffers, and re-encode the attestation for
the complete call. The credential id never leaves this process in
raw form — the API addresses credentials by sha256 ref.
*/

export function webauthnSupported(): boolean {
  return typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined';
}

function b64d(s: string): ArrayBuffer {
  const pad = '='.repeat((-s.length) % 4);
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function b64e(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Server option fields that must be ArrayBuffers, not strings.
const BIN_FIELDS = new Set(['challenge', 'id', 'user']);

function decodeOptions(opts: Record<string, unknown>):
    Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(opts)) {
    if (typeof v === 'string' && BIN_FIELDS.has(k)) {
      out[k] = b64d(v);
    } else if (k === 'user' && v && typeof v === 'object') {
      out[k] = { ...(v as object), id: b64d((v as { id: string }).id) };
    } else if (
      (k === 'excludeCredentials' || k === 'allowCredentials') &&
      Array.isArray(v)
    ) {
      out[k] = v.map((c) =>
        c && typeof c === 'object'
          ? { ...(c as object), id: b64d((c as { id: string }).id) }
          : c);
    } else {
      out[k] = v;
    }
  }
  return out;
}

export async function registerPasskey(
  options: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const cred = (await navigator.credentials.create({
    publicKey: decodeOptions(options) as unknown as
      PublicKeyCredentialCreationOptions,
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('La ceremonia fue cancelada');
  const resp = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: b64e(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: b64e(resp.attestationObject),
      clientDataJSON: b64e(resp.clientDataJSON),
    },
  };
}

/** Assertion ceremony (login): decode the request options, get() the
    credential and serialize the assertion for /auth/passkey/complete.
    allowCredentials ids arrive as base64url strings like excludeCredentials. */
export async function assertPasskey(
  options: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const decoded = decodeOptions(options);
  const cred = (await navigator.credentials.get({
    publicKey: decoded as unknown as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('La ceremonia fue cancelada');
  const resp = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: b64e(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: b64e(resp.authenticatorData),
      clientDataJSON: b64e(resp.clientDataJSON),
      signature: b64e(resp.signature),
      userHandle: resp.userHandle ? b64e(resp.userHandle) : null,
    },
  };
}
