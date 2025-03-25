import type { AuthNZOptions, Claims, Grant, IdToken, Userinfo } from '../types/index.ts';
import { AuthorizationServerError, ERROR_DESCRIPTIONS } from '../errors.ts';
import { getScopeSet } from '../utils.ts';
import { SCOPES } from '../constants.ts';

export const getClaims = async (target: IdToken | Userinfo, grant: Grant, options: AuthNZOptions): Promise<Claims> => {
    if (!grant.claims?.sub) {
        throw new AuthorizationServerError(ERROR_DESCRIPTIONS.unable_to_provide_claims);
    }

    if (options.getClaims) {
        const requestedScopes = getScopeSet(grant.scope);

        // removing internal scopes
        if (requestedScopes.has(SCOPES.offline_access)) requestedScopes.delete(SCOPES.offline_access);
        if (requestedScopes.has(SCOPES.openid)) requestedScopes.delete(SCOPES.openid);

        return options.getClaims(target, grant.claims, requestedScopes);
    }

    return grant.claims;
}