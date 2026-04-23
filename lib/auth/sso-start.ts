import { cookies } from 'next/headers';
import { encryptPayload } from '@/lib/auth/crypto';
import {
  generateCodeVerifierServer,
  generateCodeChallengeServer,
  generateStateServer,
} from '@/lib/oauth/pkce-server';
import { getRequiredConfig } from '@/lib/oauth/token-exchange';
import { discoverOAuth } from '@/lib/oauth/discovery';
import { OAUTH_SCOPES } from '@/lib/oauth/tokens';
import { getCookieOptions } from '@/lib/oauth/cookie-config';
import { readFileEnv } from '@/lib/read-file-env';

const SSO_PENDING_COOKIE = 'sso_pending';
const SSO_PENDING_MAX_AGE = 300;

export type SsoStartResult =
  | { ok: true; authorize_url: string; state: string }
  | { ok: false; status: number; error: string };

export async function buildSsoAuthorizeUrl(
  redirectUri: string,
  locale?: string,
): Promise<SsoStartResult> {
  if (!process.env.SESSION_SECRET && !readFileEnv(process.env.SESSION_SECRET_FILE)) {
    return { ok: false, status: 500, error: 'SESSION_SECRET is required for SSO' };
  }

  const { clientId, discoveryUrl } = getRequiredConfig();
  const metadata = await discoverOAuth(discoveryUrl);

  if (!metadata?.authorization_endpoint) {
    return { ok: false, status: 502, error: 'OAuth discovery failed' };
  }

  const codeVerifier = generateCodeVerifierServer();
  const codeChallenge = generateCodeChallengeServer(codeVerifier);
  const state = generateStateServer();

  const pendingData = {
    state,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri,
    created_at: Date.now(),
  };

  const encrypted = encryptPayload(pendingData);
  const cookieStore = await cookies();
  const baseCookieOpts = getCookieOptions();
  cookieStore.set(SSO_PENDING_COOKIE, encrypted, {
    ...baseCookieOpts,
    maxAge: SSO_PENDING_MAX_AGE,
  });

  const authUrl = new URL(metadata.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', OAUTH_SCOPES);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  if (locale) {
    authUrl.searchParams.set('ui_locales', locale);
  }

  return { ok: true, authorize_url: authUrl.toString(), state };
}
