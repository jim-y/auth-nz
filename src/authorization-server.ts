import { ensureFunction } from './utils';
import {
  AccessToken,
  AuthorizationServerOptions,
  TokenRequestMeta,
  OnValidTokenCb,
  FindClient,
  FindAuthorizationCode,
  AuthorizationServer,
  CreateAuthorizationCode,
} from './types';
import {
  getAuthorizationRequestMiddleware,
  getOnDecisionMiddleware,
} from './authorization-request';
import { getValidateTokenRequestMiddleware } from './token-request';

const BASE_SERVER_OPTIONS = {
  development: true,
  sessionProperty: 'session',
  metaProperty: 'authorizationServer',
};

export const createServer = (
  options = {} as AuthorizationServerOptions
): AuthorizationServer => {
  options = { ...BASE_SERVER_OPTIONS, ...options };
  return {
    /**
     * The authorization endpoint (3.1) is only used by
     * - the authorization code grant and
     * - implicit grants
     * Requirements:
     * - the URI MUST NOT include a fragment component
     * - require TLS
     * - must support GET may support POST
     * - params without value MUST be omitted
     * - MUST ignore unrecognized params
     * - params MUST NOT be included more than once
     */
    validateAuthorizationRequest({ findClient }) {
      findClient = ensureFunction<FindClient>(
        findClient,
        options?.findClient,
        `You must either provide a callback to find a Client for ${this.validateAuthorizationRequest.name} or provide the callback in AuthorizationServerOptions`
      );

      return getAuthorizationRequestMiddleware(findClient, options);
    },

    validateTokenRequest({
      findClient,
      findAuthorizationCode,
      revokeAccessTokens,
    }) {
      findClient = ensureFunction<FindClient>(
        findClient,
        options?.findClient,
        `You must either provide a callback to find a Client for ${this.validateTokenRequest.name} or provide the callback in AuthorizationServerOptions`
      );

      findAuthorizationCode = ensureFunction<FindAuthorizationCode>(
        findAuthorizationCode,
        options?.findAuthorizationCode,
        `You must either provide a callback to find an Authorization Code for ${this.validateTokenRequest.name} or provide the callback in AuthorizationServerOptions`
      );

      return getValidateTokenRequestMiddleware(
        findClient,
        findAuthorizationCode,
        revokeAccessTokens ?? options?.revokeAccessTokens
      );
    },

    onDecision({ createAuthorizationCode }) {
      createAuthorizationCode = ensureFunction<CreateAuthorizationCode>(
        createAuthorizationCode,
        options?.createAuthorizationCode,
        `You must either provide a callback to create an Authorization Code for ${this.onDecision.name} or provide the callback in AuthorizationServerOptions`
      );

      return getOnDecisionMiddleware(createAuthorizationCode, options);
    },

    onValidToken(onValidTokenCb: OnValidTokenCb) {
      return async (req: Express.Request, res) => {
        let accessToken: AccessToken;
        try {
          accessToken = await onValidTokenCb(
            {
              ...req[options.sessionProperty][options.metaProperty],
            } as TokenRequestMeta,
            req
          );
          if (accessToken == null) {
            throw new Error('Could not create access_token');
          }
        } catch (error) {
          console.error(error);
          throw error;
        }

        res.json({
          access_token: accessToken.token,
          token_type: 'bearer',
          expires_in: accessToken.ttl,
        });
      };
    },
  };
};
