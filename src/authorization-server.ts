import { stringify } from 'querystring';
import { getFindClientFn, getFindAuthorizationCodeFn } from './utils';
import {
  AccessToken,
  AuthorizationCode,
  AuthorizationRequestMeta,
  AuthorizationServerOptions,
  TokenRequestMeta,
  OnDecisionCb,
  OnValidTokenCb,
  FindClientFunction,
  FindAuthorizationCodeFunction,
  AuthorizationServer,
} from './types';
import { getValidateAuthorizationRequestMiddleware } from './authorization-request';
import { getValidateTokenRequestMiddleware } from './token-request';

export const createServer = (
  options: AuthorizationServerOptions
): AuthorizationServer => ({
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
  validateAuthorizationRequest(findClientFn?: FindClientFunction) {
    // Get a FindClientFunction, either from params or from AuthorizationServerOptions or throw if none
    findClientFn = getFindClientFn(
      findClientFn,
      options.findClient
    ) as FindClientFunction;

    return getValidateAuthorizationRequestMiddleware(findClientFn);
  },

  validateTokenRequest(
    findClientFn?: FindClientFunction,
    findAuthorizationCodeFn?: FindAuthorizationCodeFunction
  ) {
    // Get a FindClientFunction, either from params or from AuthorizationServerOptions or throw if none
    findClientFn = getFindClientFn(
      findClientFn,
      options.findClient
    ) as FindClientFunction;

    // Get a FindAuthorizationCodeFunction, either from params or from AuthorizationServerOptions or throw if none
    findAuthorizationCodeFn = getFindAuthorizationCodeFn(
      findAuthorizationCodeFn,
      options.findAuthorizationCode
    ) as FindAuthorizationCodeFunction;

    return getValidateTokenRequestMiddleware(
      findClientFn,
      findAuthorizationCodeFn,
      options?.revokeAccessTokens
    );
  },

  onDecision(onDecisionCb: OnDecisionCb) {
    return async (req, res) => {
      const { state, client } = req.session
        .authorizationServer as AuthorizationRequestMeta;

      let code: AuthorizationCode['code'];
      try {
        code = await onDecisionCb(
          { ...req.session.authorizationServer } as AuthorizationRequestMeta,
          req
        );
        if (code == null) throw new Error('Denied consent');
      } catch (error) {
        console.error(error);
        throw new Error('Denied consent');
      }

      res.redirect(`${client.redirectUri}?${stringify({ code, state })}`);
    };
  },

  onValidToken(onValidTokenCb: OnValidTokenCb) {
    return async (req, res) => {
      let accessToken: AccessToken;
      try {
        accessToken = await onValidTokenCb(
          { ...req.session.authorizationServer } as TokenRequestMeta,
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
});
