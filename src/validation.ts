import type {
    ErrorDescription,
    ValidateClientFunction,
    OAuthClient,
    ClientValidationMeta,
    Query,
    ResponseType,
    OIDCParam
} from './types/index.ts';
import {
    ERROR_DESCRIPTIONS,
    UnauthorizedClientError,
    InvalidRequestError,
    UnsupportedResponseTypeError
} from './errors.ts';
import { sanitizeQueryParams } from './utils.ts';
import { HTTP_LITERALS, OIDC_PARAMS, RESPONSE_TYPES } from './constants.ts';

/**
 * ------------------
 * Validation Helpers
 * ------------------
 */

export const getUrl = (uri: string): URL => {
    try {
        return new URL(uri);
    } catch (error) {
        throw new InvalidRequestError(
            ERROR_DESCRIPTIONS.malformed_url,
            JSON.stringify({
                uri,
                validator: 'https://nodejs.org/api/url.html#class-url'
            })
        );
    }
};

/**
 * Throws, if the given uri contains duplicated params
 * @throws InvalidRequestError
 */
export const validateDuplicates = (params: URLSearchParams) => {
    // We must not let ambiguous urls
    // We need to do an excess check here to overcome open redirector attacks
    // It is possible for a hacker to tamper the request and add an additional
    // redirect_uri parameter at the end of the qs hoping that we will redirect
    // the code to that uri. In this case we must not redirect to redirect_uri
    // but to show an error screen for the resource owner. A flagged error won't
    // yield a redirect_uri redirect.
    for (const param of params.keys()) {
        const isFlaggedError = param === OIDC_PARAMS.client_id || param === OIDC_PARAMS.redirect_uri;
        if (params.getAll(param).length > 1) {
            throw new InvalidRequestError(ERROR_DESCRIPTIONS.duplicate_query_parameter, param, isFlaggedError);
        }
    }
};

/**
 * Throws, if the given uri contains a fragment component
 * @throws InvalidRequestError
 */
export const validateURIForFragment = (url: URL) => {
    if (url.hash != null && url.hash !== '') {
        throw new InvalidRequestError(ERROR_DESCRIPTIONS.url_fragment, 'uri must not contain a fragment');
    }
};

/**
 * Throws, if uri is not using TLS that is uri's protocol value is not "https:"
 * @throws InvalidRequestError
 */
export const validateURIForTLS = (url: URL) => {
    if (process.env.NODE_ENV && process.env.NODE_ENV !== 'development') {
        if (url.protocol !== 'https:') {
            throw new InvalidRequestError(ERROR_DESCRIPTIONS.missing_tls, 'The use of the https protocol is mandatory');
        }
    }
};

/**
 * > Authorization Servers MUST support the use of the HTTP GET and POST methods defined in RFC 7231 [RFC7231]
 * > at the Authorization Endpoint.
 * Throws, if http method is missing, or it is not "get" or "post"
 * @throws InvalidRequestError
 */
export const validateURIHttpMethodForGerOrPost = (method: string) => {
    if (!method || (method?.toLowerCase() !== HTTP_LITERALS.get && method?.toLowerCase() !== HTTP_LITERALS.post)) {
        throw new InvalidRequestError(
            ERROR_DESCRIPTIONS.invalid_http_method,
            `Only HTTP GET or POST are allowed. Found: ${method}`
        );
    }
};

/**
 * Throws, if http method is missing, or it is not "post"
 * @throws InvalidRequestError
 */
export const validateURIHttpMethodForPost = (method: string, devMode = false) => {
    if (!method || method?.toLowerCase() !== HTTP_LITERALS.post) {
        throw new InvalidRequestError(
            ERROR_DESCRIPTIONS.invalid_http_method,
            devMode ? `Only HTTP POST is allowed. Found: ${method}` : null
        );
    }
};

/**
 * response_type is mandatory
 * @param responseType
 */
export const validateResponseType = (responseType: ResponseType) => {
    if (responseType == null) {
        throw new InvalidRequestError(
            ERROR_DESCRIPTIONS.missing_response_type,
            `Possible values: ${Object.values(RESPONSE_TYPES).join()}`
        );
    }
    if (responseType !== RESPONSE_TYPES.code) {
        throw new UnsupportedResponseTypeError(
            ERROR_DESCRIPTIONS.unsupported_response_type,
            `Possible values: ${Object.values(RESPONSE_TYPES).join()}`
        );
    }
};

/**
 * client_id is mandatory
 */
export const validateClientId = (client_id: OAuthClient['client_id']) => {
    if (client_id == null) {
        throw new InvalidRequestError(ERROR_DESCRIPTIONS.missing_client_id, OIDC_PARAMS.client_id, true);
    }
};

/**
 * redirect_uri is mandatory
 */
export const validateRedirectURI = (redirect_uri: string) => {
    if (redirect_uri == null) {
        throw new InvalidRequestError(ERROR_DESCRIPTIONS.missing_redirect_uri, OIDC_PARAMS.redirect_uri, true);
    }

    try {
        new URL(redirect_uri);
    } catch (error) {
        throw new InvalidRequestError(ERROR_DESCRIPTIONS.invalid_redirect_uri, OIDC_PARAMS.redirect_uri, true);
    }
};

/**
 * Throws, if the provided value can not be found in a set of valid values
 * @throws InvalidRequestError
 */
export const validateParamValue = <T>(value: T, validValues: T[], errorDescription?: ErrorDescription) => {
    if (!value || !validValues || validValues.indexOf(value) === -1) {
        throw new InvalidRequestError(errorDescription, 'Invalid param value');
    }
};

export const validateClient = (client: OAuthClient, meta: Partial<ClientValidationMeta>): void => {
    if (client == null) {
        throw new UnauthorizedClientError(
            ERROR_DESCRIPTIONS.unregistered_client,
            "We couldn't find any client by the provided clientId",
            true
        );
    }

    if (client.client_id !== meta.clientId) {
        throw new UnauthorizedClientError(
            ERROR_DESCRIPTIONS.client_id_mismatch,
            "clientId in the request is different than the found client's clientId. Likely some bug in getClient",
            true
        );
    }

    if (meta.grantType && !client.grant_types.includes(meta.grantType)) {
        throw new UnauthorizedClientError(
            ERROR_DESCRIPTIONS.invalid_grant_type,
            "the client identified by the provided clientId can not use this grant type"
        )
    }

    // TODO check base path instead of equality
    if (!client.redirect_uris.includes(meta.redirectUri)) {
        throw new UnauthorizedClientError(
            ERROR_DESCRIPTIONS.redirect_uri_mismatch,
            "redirectUri in the request is different than the found client's redirectUri. These two should match. In this version we do equality checks. basePath matching in future versions",
            true
        );
    }

    if (meta.clientSecret && client.client_secret !== meta.clientSecret) {
        throw new UnauthorizedClientError(ERROR_DESCRIPTIONS.invalid_client_secret, 'Invalid client secret');
    }
};
