import type {
    Grant,
    AuthorizationRequestMeta,
    AuthNZOptions,
    OAuthClient, TokenRequestMeta, Claims
} from '../types/index.ts';
import { randomUUID } from 'node:crypto';
import { ERROR_DESCRIPTIONS, InvalidGrantError, InvalidScopeError } from '../errors.js';

export const createAuthorizationGrant = async (
    authorizationRequestMeta: AuthorizationRequestMeta,
    claims: Claims,
    options: AuthNZOptions
): Promise<Grant> => {
    const authorizationGrantModel: Grant = {
        id: randomUUID(),
        code: randomUUID(),
        clientId: authorizationRequestMeta.client_id,
        redirectUri: authorizationRequestMeta.redirect_uri,
        expiresAt: Date.now() + options.authorizationCodeTTL,
        scope: Array.from(authorizationRequestMeta.scopeSet.values()).join(' '),
        codeChallenge: authorizationRequestMeta.code_challenge,
        codeChallengeMethod: authorizationRequestMeta.code_challenge_method,
        claims
    };
    await options.database.insert('grant', authorizationGrantModel);
    return authorizationGrantModel;
};

export const validateGrant = async (grant: Grant, client: OAuthClient, meta: TokenRequestMeta)=> {
    if (grant == null) {
        throw new InvalidGrantError(
            ERROR_DESCRIPTIONS.invalid_grant,
            'non-existing, revoked or expired grant'
        );
    }

    if (grant.clientId !== client.client_id) {
        throw new InvalidGrantError(
            ERROR_DESCRIPTIONS.invalid_grant,
            'the grant was issued for another client'
        );
    }

    if (grant.redirectUri !== meta.redirect_uri) {
        throw new InvalidGrantError(
            ERROR_DESCRIPTIONS.invalid_grant,
            'redirect_uri mismatch'
        );
    }

    if (meta.scope && meta.scopeSet && grant.scope) {
        const grantedScopes = new Set(grant.scope.split(' '));
        const requestedScopes = meta.scopeSet;
        if (!requestedScopes.isSubsetOf(grantedScopes)) {
            throw new InvalidScopeError(
                ERROR_DESCRIPTIONS.scope_error,
                `the requested scopes are a superset of the scopes the resource owner granted. Granted scopes by the resource owner: (${grant.scope})`
            )
        }
    }
}