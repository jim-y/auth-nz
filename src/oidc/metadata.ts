import type { AuthNZOptions } from '../types/index.ts';
import { GRANT_TYPES, METADATA_LITERALS, RESPONSE_TYPES } from '../constants.ts';
import { join } from 'node:path/posix';

export const getMetadata = (req: Request, options: AuthNZOptions) => {
    const issuer = new URL(options.mountPath, options.base);
    return {
        issuer: issuer.href,
        authorization_endpoint: join(issuer.href, '/authorize'),
        token_endpoint: join(issuer.href, '/token'),
        userinfo_endpoint: join(issuer.href, '/userinfo'),
        jwks_uri: join(issuer.href, '/jwks_uri'),
        registration_endpoint: join(issuer.href, '/register'),
        scopes_supported: options.defaultScope.split(' '),
        response_types_supported: Object.values(RESPONSE_TYPES),
        response_modes_supported: ['query'],
        grant_types_supported: Object.values(GRANT_TYPES),
        token_endpoint_auth_methods_supported: [
            METADATA_LITERALS.client_secret_basic,
            METADATA_LITERALS.client_secret_post
        ]
    };
};
