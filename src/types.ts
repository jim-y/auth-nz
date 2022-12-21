export type AUTHORIZATION_REQUEST_RESPONSE_TYPE = 'code' | 'token';
export type TOKEN_REQUEST_GRANT_TYPE = 'authorization_code' | 'client_credentials';
export type CODE_CHALLENGE_METHOD_TYPE = 'sha256' | 'plain';
export enum AUTHORIZATION_GRANT_DECISION {
    DECLINED,
    GRANTED,
}

/**
 * OAUTH
 */

export type OauthParameters = {
    RESPONSE_TYPE: string;
    GRANT_TYPE: string;
    CLIENT_ID: string;
    REDIRECT_URI: string;
    CODE: string;
    SCOPE: string;
    STATE: string;

    // PKCE
    CODE_VERIFIER: string;
    CODE_CHALLENGE: string;
    CODE_CHALLENGE_METHOD: string;
};

/**
 * AUTHORIZATION SERVER
 */
export interface AuthNZService {
    settings: Settings;
    use(cb: UseFunction): void;
    validateAuthorizeRequest(req: unknown): Promise<ValidateAuthorizeRequestResponse>;
    decisionHandler(
        decision: number,
        authorizationRequestMeta: AuthorizationRequestMeta,
        user: UserModel
    ): Promise<any>;
    validateTokenRequest(req: unknown): Promise<any>;
}

export interface UseFunction {
    (settings: Settings): void;
}

export type ServerProps = {
    getClient?: Settings['getClient'];
    devMode?: boolean;
};

export type Settings = {
    getClient?(clientId: Client['clientId'], req?: unknown): Promise<Client | null>;
    getQuery(req: unknown): Query;
    getBody(req: unknown): object;
    getUri(req: unknown): string;
    getMethod(req: unknown): string;

    oauthParamsMap: OauthParameters;

    createAuthorizationCode(
        authorizationRequestMeta: AuthorizationRequestMeta,
        user: UserModel,
        codeExpirationTime: number
    ): Promise<AuthorizationCodeModel>;

    expirationTimes: {
        authorizationCode: number;
        accessToken?: number;
        refreshToken?: number;
    };

    devMode: boolean;
};

/**
 * AUTHORIZATION REQUEST
 */

export interface AuthorizationRequestMeta extends RequestMetaBase {
    responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE; // REQUIRED
    clientId: Client['clientId']; // REQUIRED

    codeChallenge?: string; // OPTIONAL / RECOMMENDED
    codeChallengeMethod?: CODE_CHALLENGE_METHOD_TYPE; // OPTIONAL / RECOMMENDED

    originalUri?: string;
}

export type AuthorizationRequestResponse = AuthorizationRequestMeta & {
    serializedMeta: string; // base64 encoded
    client: Client;
};

export type ValidateAuthorizeRequestResponse =
    | AuthorizationRequestClientError
    | AuthorizationRequestErrorMeta
    | AuthorizationRequestResponse;

export type AuthorizationRequestClientError = {
    clientError: ErrorDTO;
};

export interface AuthorizationRequestErrorMeta {
    error: ErrorDTO;
    redirectUri: Client['redirectUri'];
    redirectTo: string;
}

/**
 * FUNCTIONS
 */

export interface ValidateClientFunction {
    (client: Client, meta: Partial<ClientValidationMeta>, devMode: boolean): ErrorDTO | void;
}

/**
 * MODELS
 */

export interface Client {
    clientId: string;
    redirectUri: string;
    clientSecret: string;
    confidential: boolean;
}

export interface AuthorizationCodeModel {
    code: string;
    clientId: Client['clientId'];
    redirectUri: Client['redirectUri'];
    user: UserModel;
    expiresAt: number;
    scope?: string;
    codeChallenge?: string;
    codeChallengeMethod?: CODE_CHALLENGE_METHOD_TYPE;
}

export interface AccessToken {
    token: string;
    expiresAt: number;
    ttl: number;
}

export type UserModel = {
    id: string | number;
};

export interface Query {
    [param: string]: string | string[];
}

export interface Request {
    query: Query;
    uri?: string;
    url?: string;
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
    error_hint?: string;
    state?: string;
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

export interface TokenRequestMeta extends RequestMetaBase {
    grantType: TOKEN_REQUEST_GRANT_TYPE; // REQUIRED
    code?: AuthorizationCodeModel['code']; // OPTIONAL -> client_credentials grant
    clientId?: Client['clientId']; // OPTIONAL -> might be coming from Basic auth
    codeVerifier?: string; // OPTIONAL -> PKCE
    authorizationCode?: AuthorizationCodeModel; // OPTIONAL authorization_code grant
}

export type TokenRequestMetaBase = Omit<TokenRequestMeta, 'client'>;

export type ClientValidationMeta = Pick<Client, 'clientId' | 'clientSecret' | 'redirectUri'>;
