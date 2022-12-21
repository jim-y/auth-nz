import { stringify } from 'querystring';
import { CODE_CHALLENGE_METHOD_TYPES } from './constants';
import {
    AUTHORIZATION_REQUEST_RESPONSE_TYPE,
    Client,
    AuthorizationRequestMeta,
    ClientValidationMeta,
    ErrorDTO,
    ERROR_CODE,
    AuthorizationCodeModel,
    Settings,
    ValidateAuthorizeRequestResponse,
    UserModel,
    AUTHORIZATION_GRANT_DECISION,
} from './types';
import { snakeCaseToCamelCase } from './utils';
import { RequestErrors, ErrorCodes, AuthnzError, ErrorDescriptions } from './errors';
import {
    validateClient,
    validateMultipleRedirectUriParams,
    validateParamValue,
    validateQueryParams,
    validateURIForFragment,
    validateURIForTLS,
    validateURIHttpMethodForGerOrPost,
} from './validation';
import { randomBytes } from 'crypto';

export const getAuthorizationRequestGrant = (responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE, oauthParamsMap) => {
    const authorizationRequestGrants = {
        code: {
            type: 'authorization_code',
            responseType: 'code',
            mandatoryParams: [oauthParamsMap.RESPONSE_TYPE, oauthParamsMap.CLIENT_ID],
            optionalParams: [
                oauthParamsMap.REDIRECT_URI,
                oauthParamsMap.SCOPE,
                oauthParamsMap.STATE,
                oauthParamsMap.CODE_CHALLENGE,
                oauthParamsMap.CODE_CHALLENGE_METHOD,
            ],
        },
    };
    return authorizationRequestGrants[responseType];
};

/**
 * ---------------------
 * Authorization Request
 * ---------------------
 */

/**
 * TODO:
 * - consolidate query as a {} don't allow string
 *
 * Atomic function to validate an authorization request.
 * Accepts {req} which can be derived from an arbitrary req object
 * Returns either
 *
 * { clientError }: raised when you must not redirect to redirect_uri but you
 *                  should show some error to end_user
 *
 * { error, client }: a validation error happened, the request is malformed or
 *                    otherwise corrupted. You should redirect to redirect_uri
 *                    with the error
 *
 * { authorizationRequestMeta, client }:  there was no error while validating
 *                                        the request
 * @param req unknown
 * @param settings Settings
 * @returns
 */
export async function validateAuthorizeRequest(
    req: unknown,
    settings: Settings
): Promise<ValidateAuthorizeRequestResponse> {
    // Find & Validate Client. We must do this first, so that if any error happens
    // later we can decide whether we can redirect with the error or show an error
    // screen to the user
    let client: Client;
    const query = settings.getQuery(req);

    const clientId: Client['clientId'] | undefined = _getSingleValue<Client['clientId']>(
        query[settings.oauthParamsMap.CLIENT_ID]
    );

    const redirectUri: Client['redirectUri'] | undefined = _getSingleValue<Client['redirectUri']>(
        query[settings.oauthParamsMap.REDIRECT_URI]
    );

    const state: string | undefined = _getSingleValue<string>(query[settings.oauthParamsMap.STATE]);

    // We need to do an excess check here to overcome open redirector attacks
    // It is possible for a hacker to tamper the request and add an additional
    // redirect_uri parameter at the end of the qs hoping that we will redirect
    // the code to that uri. In this case we must not redirect but raise a
    // clientError. We will do duplicate checks for other params too, later..
    try {
        validateMultipleRedirectUriParams(query, settings);
    } catch (error) {
        const err: ErrorDTO = _getErrorDtoFromError(error);
        return {
            clientError: _onClientError(err),
        };
    }

    // If there is no clientId provided in the request we must throw an error
    if (!clientId) {
        return {
            clientError: _onClientError({
                error: ErrorCodes.invalid_request as ERROR_CODE,
                error_description: ErrorDescriptions.missing_client_id,
                state,
            }),
        };
    }

    // If we found a clientId in the request we must query the datastore for the
    // Client record
    // throw from getClient if the clientId is non-conforming to your token rules
    // or otherwise you suspect fraud
    // if, for the provided clientId you can't find a Client return null it will
    // yield an unregistered_client error
    try {
        client = await settings.getClient(clientId, req);
        // We will check if client == null in the next validateClient step
    } catch (error) {
        return {
            clientError: _onClientError({
                error: ErrorCodes.unauthorized_client as ERROR_CODE,
                error_description: ErrorDescriptions.invalid_client,
                error_hint: settings.devMode ? 'the authService.getClient function threw' : null,
                state,
            }),
        };
    }

    // If we found the Client record (or null) we do client validation
    const clientValidationError: ErrorDTO | void = validateClient(
        client,
        {
            clientId,
            redirectUri,
        } as ClientValidationMeta,
        settings.devMode
    );

    if (clientValidationError) {
        return {
            clientError: _onClientError({ ...clientValidationError, state }),
        };
    }

    try {
        const uri = settings.getUri(req);

        // the authorization request URI MUST NOT include a fragment component
        validateURIForFragment(uri, settings.devMode);

        // require TLS
        if (!settings.devMode) {
            validateURIForTLS(uri, settings.devMode);
        }

        // must support GET, may support POST
        validateURIHttpMethodForGerOrPost(settings.getMethod(req), settings.devMode);

        // response_type is mandatory
        const responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE = query[
            settings.oauthParamsMap.RESPONSE_TYPE
        ] as AUTHORIZATION_REQUEST_RESPONSE_TYPE;
        if (responseType == null) {
            throw new RequestErrors.InvalidRequestError(
                ErrorDescriptions.missing_response_type,
                settings.devMode ? JSON.stringify(query) : null
            );
        }

        // grant type validation
        const grant = getAuthorizationRequestGrant(responseType, settings.oauthParamsMap);
        if (grant == null) {
            throw new RequestErrors.UnsupportedResponseTypeError(ErrorDescriptions.unsupported_response_type);
        }

        const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];

        // params MUST NOT be included more than once
        // koa and express removes the duplicates
        validateQueryParams(query, allowedParams, settings.devMode);

        // checking mandatory params
        for (const mandatoryParam of grant.mandatoryParams) {
            if (query[mandatoryParam] == null) {
                throw new RequestErrors.InvalidRequestError(
                    ErrorDescriptions.missing_mandatory_parameter,
                    settings.devMode ? mandatoryParam : null
                );
            }
        }

        // Building the meta object
        const authorizationRequestMeta = {
            originalUri: uri,
        } as AuthorizationRequestMeta;

        for (const param of allowedParams) {
            if (query[param] != null) {
                authorizationRequestMeta[snakeCaseToCamelCase(param)] = query[param];
            }
        }

        // Validating code_challenge_method value
        if (authorizationRequestMeta.codeChallengeMethod) {
            validateParamValue<string>(
                authorizationRequestMeta.codeChallengeMethod.toLowerCase(),
                Object.keys(CODE_CHALLENGE_METHOD_TYPES),
                ErrorDescriptions.invalid_code_challenge_method
            );
        }

        const serializedMeta = Buffer.from(JSON.stringify(authorizationRequestMeta), 'utf8').toString('base64');

        return {
            ...authorizationRequestMeta,
            serializedMeta,
            client,
        };
    } catch (error) {
        const errorDto: ErrorDTO = _getErrorDtoFromError(error);
        const _redirectUri = redirectUri ?? client.redirectUri;
        const url = new URL(_redirectUri);
        const searchParams = new URLSearchParams({ ...errorDto });
        url.search = searchParams.toString();

        if (state) {
            errorDto.state = state;
        }
        return {
            error: errorDto,
            redirectUri: _redirectUri,
            redirectTo: url.toString(),
        };
    }
}

/**
 * ---------------------
 * Authorization Code
 * ---------------------
 */

export const decisionHandler = async (
    decision: number,
    authorizationRequestMeta: AuthorizationRequestMeta,
    user: UserModel,
    settings: Settings
): Promise<any> => {
    let model: AuthorizationCodeModel;

    try {
        if (decision === AUTHORIZATION_GRANT_DECISION.DECLINED) {
            throw new RequestErrors.AccessDeniedError(
                ErrorDescriptions.denied_authorization_request,
                settings.devMode ? 'the resource owner denied the grant' : null
            );
        }

        model = await settings.createAuthorizationCode(
            authorizationRequestMeta,
            user,
            settings.expirationTimes.authorizationCode
        );
        if (model == null) {
            throw new RequestErrors.AccessDeniedError(
                ErrorDescriptions.denied_authorization_request,
                settings.devMode
                    ? 'the authorization server encountered an unexpected condition that prevented it from fulfilling the request'
                    : null
            );
        }
        const query: any = { code: model.code };

        if (authorizationRequestMeta.state) {
            query.state = authorizationRequestMeta.state;
        }

        return {
            redirectTo: new URL(`${authorizationRequestMeta.redirectUri}?${stringify({ ...query })}`).toString(),
            model,
        };
    } catch (error) {
        const errorDto: ErrorDTO = _getErrorDtoFromError(error);
        if (authorizationRequestMeta.state) {
            errorDto.state = authorizationRequestMeta.state;
        }
        return {
            error: errorDto,
            redirectTo: new URL(`${authorizationRequestMeta.redirectUri}?${stringify({ ...errorDto })}`).toString(),
        };
    }
};

export const createAuthorizationCode = async (
    authorizationRequestMeta: AuthorizationRequestMeta,
    user: UserModel,
    codeExpirationTime: number
): Promise<AuthorizationCodeModel> => {
    const authorizationCodeModel: AuthorizationCodeModel = {
        code: randomBytes(12).toString('hex'),
        clientId: authorizationRequestMeta.clientId,
        redirectUri: authorizationRequestMeta.redirectUri,
        expiresAt: Date.now() + codeExpirationTime,
        scope: authorizationRequestMeta.scope,
        codeChallenge: authorizationRequestMeta.codeChallenge,
        codeChallengeMethod: authorizationRequestMeta.codeChallengeMethod,
        user,
    };
    return authorizationCodeModel;
};

/**
 * ---------------------
 *        Helpers
 * ---------------------
 */

const _onClientError = (errorDto: ErrorDTO): ErrorDTO => {
    // Don't provide state if undefined. Later this object will be stringified
    // by nodejs's qs module which would append "&state=" which we don't want to
    if (errorDto.state == null) delete errorDto.state;
    if (errorDto.error_hint == null) delete errorDto.error_hint;
    return errorDto;
};

/**
 * If {error} is instance of AuthnzError then we parse special params from the
 * error object and construct an ErrorDTO as return value
 * Otherwise, we return a generic ErrorDTO
 */
const _getErrorDtoFromError = (error: AuthnzError | Error): ErrorDTO => {
    if (error instanceof AuthnzError) {
        const resp: ErrorDTO = {
            error: error.code,
            error_description: error.description,
        };
        if (error.error_hint) {
            resp.error_hint = error.error_hint;
        }
        return resp;
    }
    return {
        error: ErrorCodes.server_error as ERROR_CODE,
        error_description: 'unidentified error',
    };
};

const _getSingleValue = <T>(value: T | T[]): T => {
    if (Array.isArray(value)) {
        return value[value.length - 1];
    }
    return value;
};
