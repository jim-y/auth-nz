import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/lib/__store-mock__';

export async function GET(req: NextRequest) {
    const url = new URL(req.url);
    const error = url.searchParams.get('error');

    if (error != null && error !== '') {
        const errorUrl = new URL('/auth/oidc/error', url.href);
        for (const [key, value] of url.searchParams.entries()) {
            errorUrl.searchParams.set(key, String(value));
        }
        return NextResponse.redirect(errorUrl.href);
    }

    const code = String(url.searchParams.get('code'));

    const tokenUrl = new URL('/api/oidc/token', url.href);
    const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: 'foo',
            client_secret: 'bar',
            redirect_uri: 'http://localhost:3000/api/callback'
        }).toString()
    });
    const tokenResponse = await response.json();
    const user = await getSession();
    if (user) {
        user.access_token = tokenResponse.access_token;
    }
    return NextResponse.redirect(new URL('/', url.href));
}
