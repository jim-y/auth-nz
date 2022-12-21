import { getQuery, getUri, getMethod, getBody } from './utils';
import { Settings, ServerProps, AuthNZService, AuthorizationRequestMeta, UserModel } from './types';
import { validateAuthorizeRequest, decisionHandler, createAuthorizationCode } from './authorization-request';
import { validateTokenRequest } from './token-request';
import { oauthParamsMap } from './constants';

export function createAuthnzService({ getClient, devMode }: ServerProps): AuthNZService {
    const settings: Settings = {
        getBody,
        getQuery,
        getUri,
        getMethod,
        createAuthorizationCode,
        oauthParamsMap,
        devMode: devMode != null ? devMode : false,
        expirationTimes: {
            authorizationCode: 60 * 1000, // 60 seconds
        },
    };

    if (getClient) settings.getClient = getClient;

    const use = (cb: (settings: Settings) => void) => {
        cb(settings);
    };

    return {
        settings,
        validateAuthorizeRequest: req => validateAuthorizeRequest(req, settings),
        decisionHandler: (decision: number, authorizationRequestMeta: AuthorizationRequestMeta, user: UserModel) =>
            decisionHandler(decision, authorizationRequestMeta, user, settings),
        validateTokenRequest: req => validateTokenRequest(req, settings),
        use,
    };
}

// export const createServer = (options = {} as AuthorizationServerOptions): AuthorizationServer => {
//     return {
//         validateTokenRequest(props: ValidateTokenRequestProps) {
//             const findClient = ensureFunction(
//                 props?.findClient,
//                 options?.findClient,
//                 `You must either provide a callback to find a Client for ${this.validateTokenRequest.name} or provide the callback in AuthorizationServerOptions`
//             );

//             const findAuthorizationCode = ensureFunction<FindAuthorizationCode>(
//                 props?.findAuthorizationCode,
//                 options?.findAuthorizationCode,
//                 `You must either provide a callback to find an Authorization Code for ${this.validateTokenRequest.name} or provide the callback in AuthorizationServerOptions`
//             );

//             return getValidateTokenRequestMiddleware(
//                 findClient,
//                 findAuthorizationCode,
//                 props?.revokeAccessTokens ?? options?.revokeAccessTokens
//             );
//         },

//         onValidToken(onValidTokenCb: OnValidTokenCb) {
//             return async (req: Express.Request, res) => {
//                 let accessToken: AccessToken;
//                 try {
//                     accessToken = await onValidTokenCb(
//                         {
//                             ...req[options.sessionProperty][options.metaProperty],
//                         } as TokenRequestMeta,
//                         req
//                     );
//                     if (accessToken == null) {
//                         throw new Error('Could not create access_token');
//                     }
//                 } catch (error) {
//                     console.error(error);
//                     throw error;
//                 }

//                 res.json({
//                     access_token: accessToken.token,
//                     token_type: 'bearer',
//                     expires_in: accessToken.ttl,
//                 });
//             };
//         },
//     };
// };
