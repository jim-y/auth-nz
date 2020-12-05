import Express from 'express';

export type AUTHORIZATION_REQUEST_RESPONSE_TYPE = 'code' | 'token';
export type TOKEN_REQUEST_GRANT_TYPE =
  | 'authorization_code'
  | 'client_credentials';
export type CODE_CHALLENGE_METHOD_TYPE = 'sha256' | 'plain';

/**
 * AUTHORIZATION SERVER
 */

export interface AuthorizationServerOptions {
  findClient?: FindClient;
  findAuthorizationCode?: FindAuthorizationCode;
  createAuthorizationCode: CreateAuthorizationCode;
  revokeAccessTokens?: RevokeAccessTokens;
  development?: boolean;
  sessionProperty?: string;
  metaProperty?: string;
}

export interface ValidateAuthorizationRequestProps {
  findClient: FindClient;
}

export interface ValidateTokenRequestProps {
  findClient?: FindClient;
  findAuthorizationCode?: FindAuthorizationCode;
  revokeAccessTokens?: RevokeAccessTokens;
}

export interface OnDecisionProps {
  createAuthorizationCode: CreateAuthorizationCode;
}

export interface AuthorizationServer {
  validateAuthorizationRequest(
    props?: ValidateAuthorizationRequestProps
  ): Express.RequestHandler;

  validateTokenRequest(props?: ValidateTokenRequestProps): Express.Handler;

  onDecision(props?: OnDecisionProps): Express.RequestHandler;
  onValidToken(onValidTokenCb: OnValidTokenCb): Express.RequestHandler;
}

/**
 * FUNCTIONS
 */

export interface FindClient {
  (clientId: Client['clientId'], req: Request): Promise<Client>;
}

export interface FindAuthorizationCode {
  (code: AuthorizationCode['code'], req: Request): Promise<AuthorizationCode>;
}

export interface CreateAuthorizationCode {
  (meta: AuthorizationRequestMeta, req: Request): Promise<
    AuthorizationCode['code']
  >;
}

export interface RevokeAccessTokens {
  (authorizationCode: AuthorizationCode): void;
}

export interface ValidateClientFunction {
  (client: Client, meta: Partial<ClientValidationMeta>): ErrorDTO | void;
}

export interface OnValidTokenCb {
  (meta: TokenRequestMeta, req: any): Promise<AccessToken>;
}

/**
 * MODELS
 */

export interface Client {
  clientId: string;
  redirectUri: string;
  clientSecret: string;
}

export interface AuthorizationCode {
  code: string;
  clientId: Client['clientId'];
  redirectUri: Client['redirectUri'];
  userId: any;
  expiresAt: number;
  used?: boolean;
  scope?: string;
  codeChallenge?: string;
  codeChallengeMethod?: CODE_CHALLENGE_METHOD_TYPE;
}

export interface AccessToken {
  token: string;
  expiresAt: number;
  ttl: number;
}

export interface Query {
  [param: string]: string | string[];
}

export interface Request {
  query: Query;
  uri: string;
  method: string; // DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT
  session?: object;
}

/**
 * ERRORS
 */

export type ERROR_CODE =
  | 'invalid_request'
  | 'unauthorized_client'
  | 'access_denied'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'server_error'
  | 'temporarily_unavailable';

export interface ErrorDTO {
  error: ERROR_CODE;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export interface AuthorizationRequestErrorMeta {
  error: ErrorDTO;
}

/**
 * HELPER
 */

export interface RequestMetaBase {
  client: Client;
  scope?: string; // OPTIONAL
  state?: string; // OPTIONAL / RECOMMENDED
  redirectUri?: Client['redirectUri']; // OPTIONAL
}

export interface AuthorizationRequestMeta extends RequestMetaBase {
  responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE; // REQUIRED
  clientId: Client['clientId']; // REQUIRED

  codeChallenge?: string; // OPTIONAL / RECOMMENDED
  codeChallengeMethod?: CODE_CHALLENGE_METHOD_TYPE; // OPTIONAL / RECOMMENDED

  // Errors
  clientError?: ErrorDTO;
  error?: ErrorDTO;
}

export type AuthorizationRequestMetaBase = Omit<
  AuthorizationRequestMeta,
  'client' | 'clientError' | 'error'
>;

export interface TokenRequestMeta extends RequestMetaBase {
  grantType: TOKEN_REQUEST_GRANT_TYPE; // REQUIRED
  code?: AuthorizationCode['code']; // OPTIONAL -> client_credentials grant
  clientId?: Client['clientId']; // OPTIONAL -> might be coming from Basic auth
  codeVerifier?: string; // OPTIONAL -> PKCE
  authorizationCode?: AuthorizationCode; // OPTIONAL authorization_code grant
}

export type TokenRequestMetaBase = Omit<TokenRequestMeta, 'client'>;

export type ClientValidationMeta = Pick<
  Client,
  'clientId' | 'clientSecret' | 'redirectUri'
>;
