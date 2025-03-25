import { createService } from 'auth-nz';
import { nextPlugin } from 'auth-nz/plugins';
import { getSession } from '@/lib/__store-mock__';

export const oidc = createService({
    base: 'http://localhost:3000',
    signingKey: 'cc7e0d44fd473002f1c42167459001140ec6389b7353f8088f4d9a95f2f596f2',
    clients: [{
        client_id: 'foo',
        client_secret: 'bar',
        redirect_uris: ['http://localhost:3000/api/callback'],
        grant_types: ['authorization_code'],
        scope: 'openid offline_access email'
    }, {
        client_id: 'postman',
        client_secret: 'secret',
        redirect_uris: ['https://oauth.pstmn.io/v1/callback'],
        grant_types: ['authorization_code'],
        scope: 'openid offline_access email profile',
    }],
    showConsent(meta) {
        return true;
    },
    async getClaims(target, claims, requestedScopes) {
        console.log('getClaims', target, claims, requestedScopes);
        return claims;
    },
    async getUser(request, requestedScopes) {
        console.log('getUser', requestedScopes);
        const user = await getSession();
        if (user) {
            return {
                sub: user.sub
            };
        }
        return null;
    },
    plugins: [nextPlugin()],
    logLevel: 1
});