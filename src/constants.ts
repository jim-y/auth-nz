import { OauthParameters } from './types';

export const oauthParamsMap: OauthParameters = {
  RESPONSE_TYPE: 'response_type',
  GRANT_TYPE: 'grant_type',
  CLIENT_ID: 'client_id',
  REDIRECT_URI: 'redirect_uri',
  CODE: 'code',
  SCOPE: 'scope',
  STATE: 'state',
  // PKCE
  CODE_VERIFIER: 'code_verifier',
  CODE_CHALLENGE: 'code_challenge',
  CODE_CHALLENGE_METHOD: 'code_challenge_method',
};

export const TOKEN_REQUEST_GRANT_TYPES = {
  authorization_code: 'authorization_code',
  client_credentials: 'client_credentials',
};

export const CODE_CHALLENGE_METHOD_TYPES = {
  s256: 's256',
  sha256: 'sha256',
  plain: 'plain',
};
