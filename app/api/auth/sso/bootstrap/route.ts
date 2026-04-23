import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { buildSsoAuthorizeUrl } from '@/lib/auth/sso-start';

/**
 * Wrapper GET 302 direct : appelle buildSsoAuthorizeUrl (in-process)
 * et redirige vers authorize_url Zitadel. Remplace l'ancien fetch HTTP
 * interne vers /api/auth/sso/start qui échouait via Traefik en self-origin.
 */
export async function GET(req: NextRequest) {
  // BASE_URL est l'URL publique (Traefik). nextUrl.origin donne l'URL
  // interne (ex: 0.0.0.0:3000) quand Next.js est derrière un proxy, ce qui
  // génère un redirect_uri invalide pour Zitadel.
  const origin = process.env.BASE_URL || req.nextUrl.origin;
  const redirectUri = `${origin}/api/auth/sso/complete`;
  const locale = req.nextUrl.searchParams.get('locale') || undefined;

  try {
    const result = await buildSsoAuthorizeUrl(redirectUri, locale);
    if (!result.ok) {
      logger.warn('SSO bootstrap failed', { error: result.error, status: result.status });
      return NextResponse.json({ error: result.error }, { status: result.status });
    }
    return NextResponse.redirect(result.authorize_url, 302);
  } catch (e) {
    logger.error('SSO bootstrap error', { error: (e as Error).message });
    return NextResponse.json(
      { error: 'sso_bootstrap_error', message: (e as Error).message },
      { status: 500 },
    );
  }
}
