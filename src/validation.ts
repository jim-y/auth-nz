import { ValidateClientFunction, Client, ClientValidationMeta, ErrorDTO, ERROR_CODE, Settings, Query } from './types';
import { ErrorCodes, ErrorDescriptions, RequestErrors } from './errors';
import { sanitizeQueryParams } from './utils';

/**
 * ------------------
 * Validation Helpers
 * ------------------
 */

/**
 * Throws, if the given uri contains a fragment component
 * @throws InvalidRequestError
 */
export const validateURIForFragment = (uri: string, devMode = false) => {
    let url;

    try {
        url = new URL(uri);
    } catch (error) {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.malformed_url,
            devMode
                ? JSON.stringify({
                      uri,
                      validator: 'https://nodejs.org/api/url.html#class-url',
                  })
                : null
        );
    }

    if (url.hash != null && url.hash !== '') {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.url_fragment,
            devMode ? 'uri must not contain a fragment' : null
        );
    }
};

/**
 * Throws, if uri is not using TLS that is uri's protocol value is not "https:"
 * @throws InvalidRequestError
 */
export const validateURIForTLS = (uri: string, devMode = false) => {
    let url;

    try {
        url = new URL(uri);
    } catch (error) {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.malformed_url,
            devMode
                ? JSON.stringify({
                      uri,
                      validator: 'https://nodejs.org/api/url.html#class-url',
                  })
                : null
        );
    }

    if (url.protocol !== 'https:') {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.missing_tls,
            devMode
                ? JSON.stringify({
                      uri,
                  })
                : null
        );
    }
};

/**
 * Throws, if http method is missing or it is not "get" or "post"
 * @throws InvalidRequestError
 */
export const validateURIHttpMethodForGerOrPost = (method: string, devMode = false) => {
    if (!method || (method?.toLowerCase() !== 'get' && method?.toLowerCase() !== 'post')) {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.invalid_http_method,
            devMode ? `Only HTTP GET or POST are allowed. Found: ${method}` : null
        );
    }
};

/**
 * Throws, if http method is missing or it is not "post"
 * @throws InvalidRequestError
 */
export const validateURIHttpMethodForPost = (method: string, devMode = false) => {
    if (!method || method?.toLowerCase() !== 'post') {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.invalid_http_method,
            devMode ? `Only HTTP POST is allowed. Found: ${method}` : null
        );
    }
};

/**
 * Throws, if the query component contains duplicated keys
 * @throws InvalidRequestError
 */
export const validateQueryParams = (query: string | object, validParams: string[], devMode = false) => {
    const _query = sanitizeQueryParams(query, validParams);

    const paramKeys: string[] = Object.keys(_query);
    const uniqueParamKeys = new Set(paramKeys);

    // it is also possible that koa,express will create an array of values when
    // parsing the qs
    // E.g from express docs : GET /shoes?color[]=blue&color[]=black&color[]=red
    // console.dir(req.query.color) => [blue, black, red]
    if (paramKeys.length !== uniqueParamKeys.size || Object.values(_query).some(val => Array.isArray(val))) {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.duplicate_query_parameter,
            devMode ? JSON.stringify(query) : null
        );
    }
};

export const validateBodyParameters = (body: object, devMode = false) => {
    const paramKeys: string[] = Object.keys(body);
    const uniqueParamKeys = new Set(paramKeys);
    if (paramKeys.length !== uniqueParamKeys.size || Object.values(body).some(val => Array.isArray(val))) {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.duplicate_body_parameter,
            devMode ? JSON.stringify(body) : null
        );
    }
};

export const validateMultipleRedirectUriParams = (query: Query, { oauthParamsMap, devMode }: Settings) => {
    const redirectUriValue = query[oauthParamsMap.REDIRECT_URI];
    const numOfRedirectUriParams = Object.keys(query).filter(key => key === oauthParamsMap.REDIRECT_URI).length;

    if (numOfRedirectUriParams > 1 || (Array.isArray(redirectUriValue) && redirectUriValue.length > 1)) {
        throw new RequestErrors.InvalidRequestError(
            ErrorDescriptions.duplicate_query_parameter,
            devMode ? 'multiple redirect_uri' : null
        );
    }
};

/**
 * Throws, if the provided value can not be found in a set of valid values
 * @throws InvalidRequestError
 */
export const validateParamValue = <T>(value: T, validValues: T[], errorDescription?: string) => {
    if (!value || !validValues || validValues.indexOf(value) === -1) {
        throw new RequestErrors.InvalidRequestError(errorDescription);
    }
};

export const validateClient: ValidateClientFunction = (
    client: Client,
    meta: Partial<ClientValidationMeta>,
    devMode: Settings['devMode'] = false
): ErrorDTO | void => {
    if (client == null) {
        return {
            error: ErrorCodes.unauthorized_client as ERROR_CODE,
            error_description: ErrorDescriptions.unregistered_client,
            error_hint: devMode ? "authService.getClient didn't find any client by the provided clientId" : null,
        };
    }

    if (client.clientId !== meta.clientId) {
        return {
            error: ErrorCodes.unauthorized_client as ERROR_CODE,
            error_description: ErrorDescriptions.invalid_client_id,
            error_hint: devMode
                ? "clientId in the request is different than the found client's clientId. Likely some bug in getClient"
                : null,
        };
    }

    // TODO check base path instead of equality
    if (meta.redirectUri && client.redirectUri !== meta.redirectUri) {
        return {
            error: ErrorCodes.unauthorized_client as ERROR_CODE,
            error_description: ErrorDescriptions.invalid_redirect_uri,
            error_hint: devMode
                ? "redirectUri in the request is different than the found client's redirectUri. These two should match. In this version we do equality checks. basePath matching in future versions"
                : null,
        };
    }

    if (!meta.redirectUri && !client.redirectUri) {
        return {
            error: ErrorCodes.unauthorized_client as ERROR_CODE,
            error_description: ErrorDescriptions.missing_redirect_uri,
        };
    }

    if (meta.clientSecret && client.clientSecret !== meta.clientSecret) {
        return {
            error: ErrorCodes.unauthorized_client as ERROR_CODE,
            error_description: ErrorDescriptions.invalid_client_secret,
        };
    }
};
