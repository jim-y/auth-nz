/**
 * TODO: add i18n support
 */

import { ERROR_CODE } from './types';

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
};

export const ERROR_DESCRIPTIONS = {
  missing_client_id: 'client_id missing',
  invalid_client: 'invalid client',
  unregistered_client: 'unregistered client',
  invalid_client_id: 'invalid client_id',
  invalid_redirect_uri: 'invalid redirect_uri',
  missing_redirect_uri: 'missing redirection_uri',
  invalid_client_secret: 'invalid client_secret',
  malformed_url: 'malformed url',
  url_fragment: 'the request must not contain a url fragment',
  missing_tls: 'must use TLS',
  invalid_http_method:
    'for the authorization request only http get and post methods are supported',
  missing_response_type: 'the "response_type" parameter is mandatory',
  unsupported_response_type: 'unsupported response_type',
  duplicate_query_parameter: 'duplicated query parameter',
  invalid_code_challenge_method: 'pkce code_challenge_method transform algorithm not supported'
};

export class AuthnzError extends Error {
  code: ERROR_CODE;
  type = 'auth-nz';
  constructor(public description?: string) {
    super();
    // Set the prototype explicitly.
    // @see https://github.com/Microsoft/TypeScript-wiki/blob/master/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
    Object.setPrototypeOf(this, AuthnzError.prototype);
  }
}

export class InvalidRequestError extends AuthnzError {
  code = ERROR_CODES.invalid_request as ERROR_CODE;
  constructor(d?: string) {
    super(d);
    Object.setPrototypeOf(this, InvalidRequestError.prototype);
  }
}

export class UnauthorizedClientError extends AuthnzError {
  code = ERROR_CODES.unauthorized_client as ERROR_CODE;
  constructor(d?: string) {
    super(d);
    Object.setPrototypeOf(this, UnauthorizedClientError.prototype);
  }
}

export class AccessDeniedError extends AuthnzError {
  code = ERROR_CODES.access_denied as ERROR_CODE;
  constructor(d?: string) {
    super(d);
    Object.setPrototypeOf(this, AccessDeniedError.prototype);
  }
}

export class UnsupportedResponseTypeError extends AuthnzError {
  code = ERROR_CODES.unsupported_response_type as ERROR_CODE;
  constructor(d?: string) {
    super(d);
    Object.setPrototypeOf(this, UnsupportedResponseTypeError.prototype);
  }
}

export class InvalidScopeError extends AuthnzError {
  code = ERROR_CODES.invalid_scope as ERROR_CODE;
  constructor(d?: string) {
    super(d);
    Object.setPrototypeOf(this, InvalidScopeError.prototype);
  }
}

export class AuthorizationServerError extends AuthnzError {
  code = ERROR_CODES.server_error as ERROR_CODE;
  constructor(d?: string) {
    super(d);
    Object.setPrototypeOf(this, AuthorizationServerError.prototype);
  }
}

export class TemporarilyUnavailableError extends AuthnzError {
  code = ERROR_CODES.temporarily_unavailable as ERROR_CODE;
  constructor(d?: string) {
    super(d);
    Object.setPrototypeOf(this, TemporarilyUnavailableError.prototype);
  }
}

export const AuthorizationRequest = {
  InvalidRequestError,
  UnauthorizedClientError,
  AccessDeniedError,
  UnsupportedResponseTypeError,
  InvalidScopeError,
  AuthorizationServerError,
  TemporarilyUnavailableError,
};
