import { NextRequest, NextResponse } from 'next/server';

/**
 * Fork OIDC : wrapper GET qui fait lui-même le POST interne vers
 * /api/auth/sso/start et 302 vers l'authorize_url retourné. Permet
 * un auto-redirect server-side depuis un Traefik redirectregex ou
 * middleware Next.js, sans JS côté client.
 */
export async function GET(req: NextRequest) {
  const origin = req.nextUrl.origin;
  const redirectUri = `${origin}/api/auth/sso/complete`;

  try {
    const res = await fetch(`${origin}/api/auth/sso/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        cookie: req.headers.get('cookie') || '',
      },
      body: JSON.stringify({ redirect_uri: redirectUri, locale: 'en' }),
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: 'sso_bootstrap_failed', status: res.status },
        { status: 500 },
      );
    }

    const data = (await res.json()) as { authorize_url?: string };
    if (!data.authorize_url) {
      return NextResponse.json({ error: 'no_authorize_url' }, { status: 500 });
    }

    const response = NextResponse.redirect(data.authorize_url, 302);
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) response.headers.set('set-cookie', setCookie);
    return response;
  } catch (e) {
    return NextResponse.json(
      { error: 'sso_bootstrap_error', message: (e as Error).message },
      { status: 500 },
    );
  }
}
