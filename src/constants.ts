export const PARAMETERS = {
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

export const AUTHORIZATION_REQUEST_GRANTS = {
  code: {
    type: 'authorization_code',
    responseType: 'code',
    mandatoryParams: [PARAMETERS.RESPONSE_TYPE, PARAMETERS.CLIENT_ID],
    optionalParams: [
      PARAMETERS.REDIRECT_URI,
      PARAMETERS.SCOPE,
      PARAMETERS.STATE,
      PARAMETERS.CODE_CHALLENGE,
      PARAMETERS.CODE_CHALLENGE_METHOD,
    ],
  },
  token: {
    type: 'implicit',
    responseType: 'token',
    mandatoryParams: [],
    optionalParams: [],
  },
};

export const TOKEN_REQUEST_GRANT_TYPES = {
  authorization_code: 'authorization_code',
  client_credentials: 'client_credentials',
};

export const TOKEN_REQUEST = {
  [TOKEN_REQUEST_GRANT_TYPES.authorization_code]: {
    type: TOKEN_REQUEST_GRANT_TYPES.authorization_code,
    mandatoryParams: [PARAMETERS.GRANT_TYPE, PARAMETERS.CODE],
    optionalParams: [
      PARAMETERS.REDIRECT_URI,
      PARAMETERS.CLIENT_ID,
      PARAMETERS.CODE_VERIFIER,
      PARAMETERS.SCOPE
    ],
  },
  // TODO allow this grant only for confidential clients
  [TOKEN_REQUEST_GRANT_TYPES.client_credentials]: {
    type: TOKEN_REQUEST_GRANT_TYPES.client_credentials,
    mandatoryParams: [PARAMETERS.GRANT_TYPE],
    optionalParams: [PARAMETERS.SCOPE],
  },
};

export const CODE_CHALLENGE_METHOD_TYPES = {
  sha256: 'sha256',
  plain: 'plain',
};
