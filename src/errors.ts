/**
 * TODO: add i18n support
 */

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

export class AuthnzError extends Error {
  type = 'auth-nz';
  constructor() {
    super();
    // Set the prototype explicitly.
    // @see https://github.com/Microsoft/TypeScript-wiki/blob/master/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
    Object.setPrototypeOf(this, AuthnzError.prototype);
  }
}

export class InvalidRequestError extends AuthnzError {
  code = ERROR_CODES.invalid_request;
  constructor() {
    super();
    Object.setPrototypeOf(this, InvalidRequestError.prototype);
  }
}

export class UnauthorizedClientError extends AuthnzError {
  code = ERROR_CODES.unauthorized_client;
  constructor() {
    super();
    Object.setPrototypeOf(this, UnauthorizedClientError.prototype);
  }
}

export class AccessDeniedError extends AuthnzError {
  code = ERROR_CODES.access_denied;
  constructor() {
    super();
    Object.setPrototypeOf(this, AccessDeniedError.prototype);
  }
}

export class UnsupportedResponseTypeError extends AuthnzError {
  code = ERROR_CODES.unsupported_response_type;
  constructor() {
    super();
    Object.setPrototypeOf(this, UnsupportedResponseTypeError.prototype);
  }
}

export class InvalidScopeError extends AuthnzError {
  code = ERROR_CODES.invalid_scope;
  constructor() {
    super();
    Object.setPrototypeOf(this, InvalidScopeError.prototype);
  }
}

export class AuthorizationServerError extends AuthnzError {
  code = ERROR_CODES.server_error;
  constructor() {
    super();
    Object.setPrototypeOf(this, AuthorizationServerError.prototype);
  }
}

export class TemporarilyUnavailableError extends AuthnzError {
  code = ERROR_CODES.temporarily_unavailable;
  constructor() {
    super();
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
