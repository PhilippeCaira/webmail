import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { logger } from '@/lib/logger';
import { decryptPayload } from '@/lib/auth/crypto';
import { exchangeCodeForTokens } from '@/lib/oauth/token-exchange';
import { refreshTokenCookieName } from '@/lib/oauth/tokens';
import { getCookieOptions } from '@/lib/oauth/cookie-config';

const SSO_PENDING_COOKIE = 'sso_pending';
const SSO_PENDING_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes

type CompleteResult =
  | { ok: true; access_token?: string; expires_in?: number }
  | { ok: false; status: number; error: string };

async function completeSsoFlow(code: string, state: string): Promise<CompleteResult> {
  const cookieStore = await cookies();

  const pendingCookie = cookieStore.get(SSO_PENDING_COOKIE)?.value;
  if (!pendingCookie) {
    logger.warn('SSO complete: no pending cookie found');
    return { ok: false, status: 400, error: 'No pending SSO session' };
  }

  const pending = decryptPayload(pendingCookie);
  if (!pending) {
    cookieStore.delete(SSO_PENDING_COOKIE);
    return { ok: false, status: 400, error: 'Invalid SSO session' };
  }

  if (pending.state !== state) {
    cookieStore.delete(SSO_PENDING_COOKIE);
    logger.warn('SSO complete: state mismatch');
    return { ok: false, status: 400, error: 'State mismatch' };
  }

  const createdAt = pending.created_at as number;
  if (!createdAt || Date.now() - createdAt > SSO_PENDING_MAX_AGE_MS) {
    cookieStore.delete(SSO_PENDING_COOKIE);
    return { ok: false, status: 400, error: 'SSO session expired' };
  }

  const codeVerifier = pending.code_verifier as string;
  const redirectUri = pending.redirect_uri as string;
  if (!codeVerifier || !redirectUri) {
    cookieStore.delete(SSO_PENDING_COOKIE);
    return { ok: false, status: 400, error: 'Invalid SSO session data' };
  }

  try {
    const tokens = await exchangeCodeForTokens(code, codeVerifier, redirectUri);
    if (tokens.refresh_token) {
      cookieStore.set(refreshTokenCookieName(0), tokens.refresh_token, getCookieOptions());
    }
    cookieStore.delete(SSO_PENDING_COOKIE);
    return { ok: true, access_token: tokens.access_token, expires_in: tokens.expires_in };
  } catch (error) {
    cookieStore.delete(SSO_PENDING_COOKIE);
    logger.error('SSO complete error', { error: error instanceof Error ? error.message : 'Unknown error' });
    return { ok: false, status: 401, error: 'Token exchange failed' };
  }
}

export async function POST(request: NextRequest) {
  try {
    const { code, state } = await request.json();
    if (!code || !state) {
      return NextResponse.json({ error: 'Missing code or state' }, { status: 400 });
    }
    const result = await completeSsoFlow(code, state);
    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }
    return NextResponse.json({ access_token: result.access_token, expires_in: result.expires_in });
  } catch (error) {
    logger.error('SSO complete POST error', { error: error instanceof Error ? error.message : 'Unknown error' });
    return NextResponse.json({ error: 'Token exchange failed' }, { status: 401 });
  }
}

// GET handler pour le callback direct depuis Zitadel (redirect_uri pointe
// vers /api/auth/sso/complete avec code+state en querystring).
export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get('code') || '';
  const state = request.nextUrl.searchParams.get('state') || '';
  if (!code || !state) {
    return NextResponse.json({ error: 'Missing code or state' }, { status: 400 });
  }
  const result = await completeSsoFlow(code, state);
  if (!result.ok) {
    logger.warn('SSO complete GET failed', { error: result.error, status: result.status });
    return NextResponse.redirect(
      new URL(`/en/login?sso_error=${encodeURIComponent(result.error)}`, process.env.BASE_URL || request.nextUrl.origin),
      302,
    );
  }
  // Redirect vers la home app; les cookies session/refresh_token sont déjà set.
  return NextResponse.redirect(new URL('/', process.env.BASE_URL || request.nextUrl.origin), 302);
}
