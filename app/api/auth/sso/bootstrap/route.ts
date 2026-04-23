import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { buildSsoAuthorizeUrl } from '@/lib/auth/sso-start';

/**
 * Wrapper GET 302 direct : appelle buildSsoAuthorizeUrl (in-process)
 * et redirige vers authorize_url Zitadel. Remplace l'ancien fetch HTTP
 * interne vers /api/auth/sso/start qui échouait via Traefik en self-origin.
 */
export async function GET(req: NextRequest) {
  const origin = req.nextUrl.origin;
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
