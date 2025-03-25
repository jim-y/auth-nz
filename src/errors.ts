/**
 * TODO: add i18n support
 */

import type { AuthNZOptions, ErrorCode, ErrorDescription, ErrorDTO } from './types/index.ts';

export const ERROR_CODES = {
    // The request is missing a required parameter, includes an invalid parameter
    // value, includes a parameter more than once, or is otherwise malformed
    invalid_request: 'invalid_request',

    // The client is not authorized to request an authorization code using this
    // method
    unauthorized_client: 'unauthorized_client',

    // The resource owner or authorization server denied the request
    access_denied: 'access_denied',

    // The authorization server does not support obtaining an authorization code
    // using this method
    unsupported_response_type: 'unsupported_response_type',

    // The requested scope is invalid, unknown, or malformed
    invalid_scope: 'invalid_scope',

    // The authorization server encountered an unexpected condition that prevented
    // it from fulfilling the request. In place of a HTTP 500
    server_error: 'server_error',

    // The authorization server is currently unable to handle the request due to a
    // temporary overloading or maintenance of the server. In place of a HTTP 503
    temporarily_unavailable: 'temporarily_unavailable',

    // The authorization server does not support the provided grant type on the
    // token request
    unsupported_grant_type: 'unsupported_grant_type',

    // Client authentication failed (e.g., unknown client, no
    // client authentication included, or unsupported
    // authentication method).  The authorization server MAY
    // return an HTTP 401 (Unauthorized) status code to indicate
    // which HTTP authentication schemes are supported.  If the
    // client attempted to authenticate via the "Authorization"
    // request header field, the authorization server MUST
    // respond with an HTTP 401 (Unauthorized) status code and
    // include the "WWW-Authenticate" response header field
    // matching the authentication scheme used by the client.
    invalid_client: 'invalid_client',

    // The provided authorization grant (e.g., authorization
    // code, resource owner credentials) or refresh token is
    // invalid, expired, revoked, does not match the redirection
    // URI used in the authorization request, or was issued to
    // another client.
    invalid_grant: 'invalid_grant',
} as const;

export const ERROR_DESCRIPTIONS = {
    missing_client_id: 'client_id missing',
    invalid_client: 'invalid client',
    unregistered_client: 'unregistered client',
    invalid_client_id: 'invalid client_id',
    client_id_mismatch:
        "mismatching client_id. the client_id provided with the request does not match with the registered client's client_id",
    invalid_redirect_uri: 'invalid redirect_uri. the redirect_uri might be malformed.',
    missing_redirect_uri: 'missing redirection_uri',
    redirect_uri_mismatch: 'mismatching redirect_uri',
    invalid_client_secret: 'invalid client_secret',
    malformed_url: 'malformed url',
    url_fragment: 'the request must not contain a url fragment',
    missing_tls: 'must use TLS',
    missing_mandatory_parameter: 'missing mandatory parameter',
    invalid_content_type: 'invalid content_type',
    invalid_http_method: 'for the authorization request only http get and post methods are supported',
    missing_response_type: 'the "response_type" parameter is mandatory',
    unsupported_response_type: 'unsupported response_type',
    duplicate_query_parameter: 'duplicated query parameter',
    duplicate_body_parameter: 'duplicated body parameter',
    missing_client_authentication_parameters: 'missing client_authentication_parameters',
    invalid_code_challenge_method: 'pkce code_challenge_method transform algorithm not supported',
    denied_authorization_request: 'the resource owner or authorization server denied the request',
    unsupported_grant_type: 'the grant type is not supported',
    unsupported_grant_type_for_client: 'the provided grant type is invalid for the client',
    invalid_grant_type: 'the grant type is not usable for this client',
    invalid_scope: 'invalid scope value provided with the request',
    scope_error: 'The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner',
    invalid_client_authentication: 'invalid_client_authentication',
    public_client_must_not_authenticate: 'public clients must not authenticate with the authorization server',
    confidential_clients_must_authenticate: 'confidential_clients_must_authenticate',
    multiple_client_authentication_mechanism: 'multiple_client_authentication_mechanism',
    invalid_grant: 'The provided authorization grant or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client',
    unable_to_provide_claims: 'the authorization server were unable to provide claims due to an invalid configuration'
} as const;

export class AuthnzError extends Error {
    type = 'auth-nz';

    code: ErrorCode;
    description: ErrorDescription;
    error_hint: string;
    flagged: boolean;
    state: string;

    #redirect_uri: string;

    constructor(description?: ErrorDescription, error_hint?: string, flagged: boolean = false) {
        super();
        this.description = description;
        this.error_hint = error_hint;
        this.flagged = flagged;
        // Set the prototype explicitly.
        // @see https://github.com/Microsoft/TypeScript-wiki/blob/master/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
        Object.setPrototypeOf(this, AuthnzError.prototype);
    }

    set redirect_uri(redirect_uri: string) {
        if (!this.flagged) {
            this.#redirect_uri = redirect_uri;
        }
    }

    get redirect_uri() {
        return this.#redirect_uri;
    }
}

export class InvalidRequestError extends AuthnzError {
    code = ERROR_CODES.invalid_request;

    constructor(description: ErrorDescription, hint: string, flagged: boolean = false) {
        super(description, hint, flagged);
        Object.setPrototypeOf(this, InvalidRequestError.prototype);
    }
}

export class UnauthorizedClientError extends AuthnzError {
    code = ERROR_CODES.unauthorized_client;

    constructor(description: ErrorDescription, hint: string, flagged: boolean = false) {
        super(description, hint, flagged);
        Object.setPrototypeOf(this, UnauthorizedClientError.prototype);
    }
}

export class AccessDeniedError extends AuthnzError {
    code = ERROR_CODES.access_denied;

    constructor(description?: ErrorDescription, hint?: string) {
        super(description, hint);
        Object.setPrototypeOf(this, AccessDeniedError.prototype);
    }
}

export class UnsupportedResponseTypeError extends AuthnzError {
    code = ERROR_CODES.unsupported_response_type;

    constructor(description?: ErrorDescription, hint?: string) {
        super(description, hint);
        Object.setPrototypeOf(this, UnsupportedResponseTypeError.prototype);
    }
}

export class InvalidScopeError extends AuthnzError {
    code = ERROR_CODES.invalid_scope;

    constructor(description?: ErrorDescription, hint?: string) {
        super(description, hint);
        Object.setPrototypeOf(this, InvalidScopeError.prototype);
    }
}

export class AuthorizationServerError extends AuthnzError {
    code = ERROR_CODES.server_error;

    constructor(description?: ErrorDescription, hint?: string) {
        super(description, hint);
        Object.setPrototypeOf(this, AuthorizationServerError.prototype);
    }
}

export class TemporarilyUnavailableError extends AuthnzError {
    code = ERROR_CODES.temporarily_unavailable;

    constructor(description?: ErrorDescription, hint?: string) {
        super(description, hint);
        Object.setPrototypeOf(this, TemporarilyUnavailableError.prototype);
    }
}

export class UnsupportedGrantTypeError extends AuthnzError {
    code = ERROR_CODES.unsupported_grant_type;

    constructor(description?: ErrorDescription, hint?: string) {
        super(description, hint);
        Object.setPrototypeOf(this, UnsupportedGrantTypeError.prototype);
    }
}

export class InvalidClientError extends AuthnzError {
    code = ERROR_CODES.invalid_client;

    constructor(description?: ErrorDescription, hint?: string) {
        super(description, hint);
        Object.setPrototypeOf(this, InvalidClientError.prototype);
    }
}

export class InvalidGrantError extends AuthnzError {
    code = ERROR_CODES.invalid_grant;

    constructor(description?: ErrorDescription, hint?: string) {
        super(description, hint);
        Object.setPrototypeOf(this, InvalidGrantError.prototype);
    }
}

export const handleError = (error: ErrorDTO, options: AuthNZOptions): Response => {
    let errorUrl = new URL(options.errorURL.href);
    if (error.redirect_uri) {
        errorUrl = new URL(error.redirect_uri);
        delete error.redirect_uri;
    }
    for (const errorKey in error) {
        errorUrl.searchParams.set(errorKey, error[errorKey]);
    }
    return Response.redirect(errorUrl.href);
};

export const toErrorDTO = (error: AuthnzError): ErrorDTO => {
    const errorDTO = {
        error: error.code,
        error_description: error.description,
        error_hint: error.error_hint
    } as ErrorDTO;

    if (error.state) {
        errorDTO.state = error.state;
    }

    if (!error.flagged && error.redirect_uri) {
        errorDTO.redirect_uri = error.redirect_uri;
    }

    return errorDTO;
};
