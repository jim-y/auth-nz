import { createHash } from 'crypto';
import {
  TOKEN_REQUEST_GRANT_TYPE,
  TokenRequestMetaBase,
  ClientValidationMeta,
  Client,
  FindClientFunction,
  AuthorizationCode,
  FindAuthorizationCodeFunction,
  TokenRequestMeta,
  RevokeAccessTokensFunction,
} from './types';
import {
  PARAMETERS,
  TOKEN_REQUEST,
  TOKEN_REQUEST_GRANT_TYPES,
  CODE_CHALLENGE_METHOD_TYPES,
} from './constants';
import { snakeCaseToCamelCase } from './utils';
import { BasicAuth, authenticateClient } from './client-auth';
import { validateClient } from './shared';

export const getValidateTokenRequestMiddleware = (
  findClientFn: FindClientFunction,
  findAuthorizationCodeFn: FindAuthorizationCodeFunction,
  revokeAccessTokens?: RevokeAccessTokensFunction
) => async (req, _res, next) => {
  console.log('validateTokenRequest', req.body);

  // 1) grant_type is mandatory
  const grantType: TOKEN_REQUEST_GRANT_TYPE = req.body[PARAMETERS.GRANT_TYPE];
  if (grantType == null) {
    throw new Error('grant_type parameter is required');
  }

  // 2) finding out the grant type
  const grant = TOKEN_REQUEST[grantType];
  if (grant == null) {
    throw new Error(
      'Unsupported grant type. grant_type must be either "authorization_code" or "client_credentials"'
    );
  }

  // 3) Checking mandatory params
  for (const mandatoryParam of grant.mandatoryParams) {
    if (req.body[mandatoryParam] == null) {
      throw new Error(
        `Required parameter "${mandatoryParam}" is missing from the token request`
      );
    }
  }

  // Building the meta object
  const tokenRequestMeta = {} as TokenRequestMetaBase;
  const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];
  for (const param of allowedParams) {
    if (req.body[param] != null) {
      tokenRequestMeta[snakeCaseToCamelCase(param)] = req.body[param];
    }
  }

  if (grant.type === TOKEN_REQUEST_GRANT_TYPES.authorization_code) {
    await authorizationCodeFlow(
      findClientFn,
      findAuthorizationCodeFn,
      tokenRequestMeta,
      req,
      revokeAccessTokens
    );
  } else if (grant.type === TOKEN_REQUEST_GRANT_TYPES.client_credentials) {
    await clientCredentialsFlow(findClientFn, tokenRequestMeta, req);
  } else {
    throw new Error("Couldn't validate client. Invalid client");
  }

  next();
};

const authorizationCodeFlow = async (
  findClientFn: FindClientFunction,
  findAuthorizationCodeFn: FindAuthorizationCodeFunction,
  tokenRequestMeta: TokenRequestMetaBase,
  req,
  revokeAccessTokens?: RevokeAccessTokensFunction
) => {
  // 4) Client validation/authentication
  // TODO implement client authentication
  const clientAuth: BasicAuth = authenticateClient(req);
  let isPublicClient = false;
  let client: Client;

  // The Client is NOT authenticating with the authorization server
  if (clientAuth == null) {
    // in this case "client_id" is required
    if (!tokenRequestMeta.clientId) {
      throw new Error('The "client_id" parameter is missing!');
    }
    isPublicClient = true;
  }
  // The Client is authenticating with the authorization server
  // need to validate the client
  else {
    client = await findClientFn(clientAuth.clientId, req);
    validateClient(client, {
      clientId: clientAuth.clientId,
      clientSecret: clientAuth.clientSecret,
    } as ClientValidationMeta);
  }

  // 5) Code validation
  let authorizationCode: AuthorizationCode;
  try {
    authorizationCode = await findAuthorizationCodeFn(
      tokenRequestMeta.code,
      req
    );

    if (authorizationCode == null) {
      throw new Error('Invalid authorization code.');
    }

    if (
      authorizationCode.expiresAt &&
      Date.now() > authorizationCode.expiresAt
    ) {
      throw new Error('Invalid authorization code. Code expired!');
    }

    if (
      authorizationCode.clientId !==
      (isPublicClient ? tokenRequestMeta.clientId : client.clientId)
    ) {
      throw new Error('Invalid authorization code. Client ID mismatch!');
    }

    // 4.1.3 Access Token Request
    // REQUIRED, if the "redirect_uri" parameter was included in the authorization request
    if (authorizationCode.redirectUri && !tokenRequestMeta.redirectUri) {
      throw new Error('Missing Redirect URI!');
    }

    // 4.1.3 Access Token Request
    // if the "redirect_uri" parameter was included in the authorization request and their
    // values MUST be identical
    if (
      tokenRequestMeta.redirectUri &&
      authorizationCode.redirectUri &&
      authorizationCode.redirectUri !== tokenRequestMeta.redirectUri
    ) {
      throw new Error('Invalid authorization code. Redirect URI mismatch!');
    }

    if (authorizationCode.used != null && authorizationCode.used === true) {
      revokeAccessTokens?.(authorizationCode);
      throw new Error('Invalid authorization code. Code already used!');
    }
  } catch (error) {
    console.error(error);
    throw error;
  }

  // 6) PKCE
  if (isPublicClient) {
    if (
      !tokenRequestMeta.codeVerifier ||
      !authorizationCode.codeChallenge ||
      !authorizationCode.codeChallengeMethod
    ) {
      throw new Error(
        'Public Clients using the authorization_code flow MUST use the PKCE extension'
      );
    }

    if (
      authorizationCode.codeChallengeMethod ===
        CODE_CHALLENGE_METHOD_TYPES.plain &&
      tokenRequestMeta.codeVerifier !== authorizationCode.codeChallenge
    ) {
      throw new Error('Invalid code_verifier');
    }

    if (
      authorizationCode.codeChallengeMethod ===
      CODE_CHALLENGE_METHOD_TYPES.sha256
    ) {
      const hashFunction = createHash('sha256');
      const hex = hashFunction
        .update(tokenRequestMeta.codeVerifier)
        .digest('hex');
      const challenge = Buffer.from(hex).toString('base64');
      if (challenge !== authorizationCode.codeChallenge) {
        throw new Error('Invalid code challenge');
      }
    }
  }

  req.session.authorizationServer = {
    ...tokenRequestMeta,
    client,
    authorizationCode,
  };
};

const clientCredentialsFlow = async (
  findClientFn: FindClientFunction,
  tokenRequestMeta: TokenRequestMetaBase,
  req
) => {
  const clientAuth: BasicAuth = authenticateClient(req);

  if (clientAuth == null) {
    throw new Error(
      'Clients using the client_credentials grant must authenticate themselfs!'
    );
  }

  const client = await findClientFn(clientAuth.clientId, req);
  validateClient(client, {
    clientId: clientAuth.clientId,
    clientSecret: clientAuth.clientSecret,
  } as ClientValidationMeta);

  req.session.authorizationServer = {
    ...tokenRequestMeta,
    client,
  } as TokenRequestMeta;
};
