import type { ObjectValues } from './helpers.ts';
import {
    AUTHORIZATION_GRANT_DECISIONS,
    AUTHORIZATION_REQUEST_GRANTS,
    GRANT_TYPES,
    ID_TOKEN,
    OIDC_PARAMS,
    RESPONSE_TYPES,
    SCOPES,
    TOKEN_REQUEST_GRANTS,
    USERINFO
} from '../constants.ts';
import { ERROR_DESCRIPTIONS, ERROR_CODES } from '../errors.ts';
import EventEmitter from 'node:events';

export type ResponseType = ObjectValues<typeof RESPONSE_TYPES>;
export type GrantType = ObjectValues<typeof GRANT_TYPES>;
export type CODE_CHALLENGE_METHOD_TYPE = 'sha256' | 'plain';
export type AUTHORIZATION_GRANT_DECISION = ObjectValues<typeof AUTHORIZATION_GRANT_DECISIONS>;

/**
 * OAUTH
 */

export type OAuthClient = {
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
    grant_types: Array<GrantType>;
    scope?: string;
    trusted?: boolean;
    client_name?: string;
    client_uri?: string;
    logo_uri?: string;
    client_type?: 'confidential' | 'public';
    client_profile?: 'web' | 'user_agent_based' | 'native';
    contacts?: string;
    jwks_uri?: string; // e.g for https://www.rfc-editor.org/rfc/rfc7523
    response_types?: Array<ResponseType>;
    sofware_id?: string;
    token_endpoint_auth_method?: 'none' | 'client_secret_post' | 'client_secret_basic';
};

export type OIDCParam = ObjectValues<typeof OIDC_PARAMS>;
export type IdToken = typeof ID_TOKEN;
export type Userinfo = typeof USERINFO;

export type TokenResponse = {
    access_token: string;
    token_type: string;
    expires_in: number;
    id_token?: string;
};

/**
 * AUTHORIZATION SERVER
 */

export type Scope = ObjectValues<typeof SCOPES>;

export type Claims = {
    sub: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    middle_name?: string;
    nickname?: string;
    preferred_username?: string;
    profile?: string;
    picture?: string;
    website?: string;
    email?: string;
    email_verified?: boolean;
    gender?: string;
    birthdate?: string;
    zoneinfo?: string;
    locale?: string;
    phone_number?: string;
    phone_number_verified?: boolean;
    address?: JSON;
    updated_at?: number;
};

export type AuthNZOptions = {
    base: string;
    mountPath?: string;
    getUser: (originalRequest: unknown, requestedScopes: Set<Scope>) => Promise<Claims | null>;
    getClaims?: (
        target: IdToken | Userinfo,
        claims: Claims,
        requestedScopes: Set<Scope>,
        requestedClaims?: Set<keyof Claims>
    ) => Promise<Claims>;
    signingKey?: string;
    database?: EventEmitter & {
        insert(table: string, payload: any, uid?: string): Promise<void>;
        fetch<TValue>(table: string, predicate: string, value?: any): Promise<TValue>;
        update(table: string, uid: string, updates: Record<string, any>): Promise<void>;
    }; // todo
    signInURL?: URL;
    consentURL?: URL;
    errorURL?: URL;
    clients?: OAuthClient[];
    plugins?: Array<AuthNZPlugin>;
    cookies?: {
        keys?: {
            login?: string;
            consent?: string;
        };
    };
    getClient?: (client_id: OAuthClient['client_id']) => Promise<OAuthClient | null>;
    defaultScope?: string;
    showConsent?: (meta: AuthorizationRequestMeta, claims: Claims) => boolean;
    authorizationCodeTTL?: number; // milliseconds
    logLevel?: number;
};

export type PluginOptions = Record<string, any>;

export type AuthNZService = {
    handler: any;
    options: AuthNZOptions;
};

/**
 * AUTHORIZATION REQUEST
 */

export type AuthorizationGrantType = ObjectValues<typeof AUTHORIZATION_REQUEST_GRANTS>;

export type Step =
    | {
          type: 'login';
          active: boolean;
          completed: boolean;
      }
    | {
          type: 'consent';
          active: boolean;
          completed: boolean;
      };

export type RequestMetaBase = {
    uid: string;
    client: OAuthClient;
    scope?: string; // OPTIONAL
    scopeSet?: Set<Scope>;
    state?: string; // OPTIONAL / RECOMMENDED
    redirect_uri?: string; // OPTIONAL
};

export type AuthorizationRequestMeta = RequestMetaBase & {
    response_type: ResponseType; // REQUIRED
    client_id: OAuthClient['client_id']; // REQUIRED

    code_challenge?: string; // OPTIONAL / RECOMMENDED
    code_challenge_method?: CODE_CHALLENGE_METHOD_TYPE; // OPTIONAL / RECOMMENDED

    original_uri?: string;
    steps?: Step[];
    claims?: Claims;
};

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
 * TOKEN REQUEST
 */

export type TokenRequestGrant = ObjectValues<typeof TOKEN_REQUEST_GRANTS>;

/**
 * FUNCTIONS
 */

export interface ValidateClientFunction {
    (client: OAuthClient, meta: Partial<ClientValidationMeta>): void | never;
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

export interface Grant {
    id: string;
    code: string;
    clientId: Client['clientId'];
    redirectUri: Client['redirectUri'];
    claims: Claims;
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

export interface Query {
    [param: string]: string | string[];
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

export type ErrorDTO = {
    error: ErrorCode;
    error_description?: string;
    error_uri?: string;
    error_hint?: string;
    state?: string;
    redirect_uri?: string;
};

export type ErrorDescription = ObjectValues<typeof ERROR_DESCRIPTIONS>;
export type ErrorCode = ObjectValues<typeof ERROR_CODES>;

/**
 * HELPER
 */

export interface TokenRequestMeta extends RequestMetaBase {
    grantType: GrantType; // REQUIRED
    client_id: OAuthClient['client_id'];
    client_secret: OAuthClient['client_secret'];
    redirect_uri: string;
    code?: Grant['code']; // OPTIONAL -> client_credentials grant
    code_verifier?: string; // OPTIONAL -> PKCE
    authorizationCode?: Grant; // OPTIONAL authorization_code grant
}

export type ClientValidationMeta = Pick<Client, 'clientId' | 'clientSecret' | 'redirectUri'> & { grantType: GrantType };

export type HTTPMethod = 'get' | 'post' | 'put' | 'patch' | 'delete' | 'options';

/**
 * PLUGINS
 */

export type AuthNZPlugin = {
    type: 'core';
    handler(options: AuthNZOptions): unknown;
};
export type AuthNZPluginFactory = (pluginOptions?: PluginOptions) => AuthNZPlugin;
