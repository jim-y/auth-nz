import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import type { AuthNZOptions, Grant, OAuthClient, TokenRequestMeta } from '../types/index.js';
import { getClaims } from './claims.ts';
import { ID_TOKEN } from '../constants.ts';

export const generateAccessToken = async (
    grant: Grant,
    client: OAuthClient,
    meta: TokenRequestMeta,
    options: AuthNZOptions
): Promise<{ access_token: string; type: string }> => {
    const secret = new TextEncoder().encode(options.signingKey);
    const alg = 'HS256';
    const payload = {
        id: randomUUID(),
        name: grant.claims.email,
        email: grant.claims.email,
        email_verified: false,
        role: 'admin',
        scope: grant.scope,
        organization: {
            name: 'Personar Ltd.',
            slug: 'personar.ai',
            id: 'dEs3NAmpWWgluzo17g3Wx1r3svl3hD0a',
            role: 'owner'
        }
    };
    const jwt = await new SignJWT(payload)
        .setProtectedHeader({ alg })
        .setIssuedAt(Date.now())
        .setSubject(grant.claims.sub)
        .setIssuer(options.base)
        .setAudience(client.client_id)
        .setExpirationTime(7200)
        .sign(secret);

    return { access_token: jwt, type: 'jwt' };
};

export const generateIdToken = async (
    grant: Grant,
    client: OAuthClient,
    meta: TokenRequestMeta,
    options: AuthNZOptions
): Promise<string> => {
    const claims = await getClaims(ID_TOKEN, grant, options);
    const sub = claims.sub;

    delete claims.sub;

    const secret = new TextEncoder().encode(options.signingKey);
    const alg = 'HS256';
    const id_token = await new SignJWT(claims)
        .setProtectedHeader({ alg })
        .setIssuedAt(Date.now())
        .setSubject(sub)
        .setIssuer(options.base)
        .setAudience(client.client_id)
        .setExpirationTime(7200)
        .sign(secret);

    return id_token;
};
