export type AUTHORIZATION_REQUEST_RESPONSE_TYPE = 'code' | 'token';
export type TOKEN_REQUEST_GRANT_TYPE =
  | 'authorization_code'
  | 'client_credentials';
export type CODE_CHALLENGE_METHOD_TYPE = 'sha256' | 'plain';

interface AsyncConnectTypeMiddleware {
  (req, res, next): Promise<void>;
}

/**
 * AUTHORIZATION SERVER
 */

export interface AuthorizationServerOptions {
  findClient: FindClientFunction;
  findAuthorizationCode: FindAuthorizationCodeFunction;
  revokeAccessTokens: RevokeAccessTokensFunction;
}

export interface AuthorizationServer {
  validateAuthorizationRequest(
    findClientFn?: FindClientFunction
  ): AsyncConnectTypeMiddleware;

  validateTokenRequest(
    findClientFn?: FindClientFunction,
    findAuthorizationCodeFn?: FindAuthorizationCodeFunction,
    revokeAccessTokens?: RevokeAccessTokensFunction
  ): AsyncConnectTypeMiddleware;

  onDecision(onDecisionCb: OnDecisionCb): AsyncConnectTypeMiddleware;
  onValidToken(onValidTokenCb: OnValidTokenCb): AsyncConnectTypeMiddleware;
}

/**
 * FUNCTIONS
 */

export interface FindClientFunction {
  (clientId: Client['clientId'], req: any): Promise<Client>;
}

export interface FindAuthorizationCodeFunction {
  (code: AuthorizationCode['code'], req: any): Promise<AuthorizationCode>;
}

export interface RevokeAccessTokensFunction {
  (authorizationCode: AuthorizationCode): void;
}

export interface ValidateClientFunction {
  (client: Client, meta: Partial<ClientValidationMeta>): void;
}

export interface OnDecisionCb {
  (meta: AuthorizationRequestMeta, req: any): Promise<
    AuthorizationCode['code']
  >;
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

/**
 * HELPER
 */

export interface RequestMetaBase {
  client: Client;
  scope?: string; // OPTIONAL
  state?: string; // OPTIONAL
  redirectUri?: Client['redirectUri']; // OPTIONAL
}

export interface AuthorizationRequestMeta extends RequestMetaBase {
  responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE; // REQUIRED
  clientId: Client['clientId']; // REQUIRED
  codeChallenge?: string; // OPTIONAL -> PKCE
  codeChallengeMethod?: CODE_CHALLENGE_METHOD_TYPE; // OPTIONAL -> PKCE
}

export type AuthorizationRequestMetaBase = Omit<
  AuthorizationRequestMeta,
  'client'
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
