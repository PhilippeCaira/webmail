import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { buildSsoAuthorizeUrl } from '@/lib/auth/sso-start';

export async function POST(request: NextRequest) {
  try {
    const { redirect_uri, locale } = await request.json();

    if (!redirect_uri || typeof redirect_uri !== 'string') {
      return NextResponse.json({ error: 'Missing redirect_uri' }, { status: 400 });
    }

    const requestOrigin = request.headers.get('origin') || request.nextUrl.origin;
    try {
      const redirectOrigin = new URL(redirect_uri).origin;
      if (redirectOrigin !== requestOrigin) {
        logger.warn('SSO start: redirect_uri origin mismatch', { redirectOrigin, requestOrigin });
        return NextResponse.json({ error: 'Invalid redirect_uri' }, { status: 400 });
      }
    } catch {
      return NextResponse.json({ error: 'Invalid redirect_uri' }, { status: 400 });
    }

    const result = await buildSsoAuthorizeUrl(redirect_uri, locale);
    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json({ authorize_url: result.authorize_url, state: result.state });
  } catch (error) {
    logger.error('SSO start error', { error: error instanceof Error ? error.message : 'Unknown error' });
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
