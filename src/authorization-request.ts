import { stringify, parse } from 'querystring';
import {
  PARAMETERS,
  AUTHORIZATION_REQUEST_GRANTS,
  CODE_CHALLENGE_METHOD_TYPES,
} from './constants';
import {
  AUTHORIZATION_REQUEST_RESPONSE_TYPE,
  Client,
  FindClientFunction,
  AuthorizationRequestMeta,
  ClientValidationMeta,
  AuthorizationRequestMetaBase,
  AuthorizationServerOptions,
  ErrorDTO,
  AuthorizationRequestErrorMeta,
  ERROR_CODE,
  Request,
  Query,
} from './types';
import { snakeCaseToCamelCase, typer, getRequest } from './utils';
import {
  AuthorizationRequest as AuthorizationRequestErrors,
  ERROR_CODES,
  AuthnzError,
  ERROR_DESCRIPTIONS,
} from './errors';
import { validateClient } from './shared';

declare var __DEV__: boolean;

/**
 * ------------------
 * Validation Helpers
 * ------------------
 */

/**
 * Throws, if the given uri contains a fragment component
 * @throws InvalidRequestError
 */
export const validateURIForFragment = (uri: string) => {
  let url;

  try {
    url = new URL(uri);
  } catch (error) {
    throw new AuthorizationRequestErrors.InvalidRequestError(
      ERROR_DESCRIPTIONS.malformed_url
    );
  }

  if (url.hash != null && url.hash !== '') {
    throw new AuthorizationRequestErrors.InvalidRequestError(
      ERROR_DESCRIPTIONS.url_fragment
    );
  }
};

/**
 * Throws, if uri is not using TLS that is uri's protocol value is not "https:"
 * @throws InvalidRequestError
 */
export const validateURIForTLS = (uri: string) => {
  let url;

  try {
    url = new URL(uri);
  } catch (error) {
    throw new AuthorizationRequestErrors.InvalidRequestError(
      ERROR_DESCRIPTIONS.malformed_url
    );
  }

  if (url.protocol !== 'https:') {
    throw new AuthorizationRequestErrors.InvalidRequestError(
      ERROR_DESCRIPTIONS.missing_tls
    );
  }
};

/**
 * Throws, if method is missing or it is not "get" or "post"
 * @throws InvalidRequestError
 */
export const validateURIHttpMethod = (method: string) => {
  if (
    !method ||
    (method?.toLowerCase() !== 'get' && method?.toLowerCase() !== 'post')
  ) {
    throw new AuthorizationRequestErrors.InvalidRequestError(
      ERROR_DESCRIPTIONS.invalid_http_method
    );
  }
};

/**
 * rfc6749#3.1: parameters sent without a value MUST be treated  as if they
 * were omitted from the request. The authorization server MUST ignore
 * unrecognized request parameters
 */
export const sanitizeQueryParams = (
  query: string | object,
  validParams: string[]
) => {
  if (typer.isString(query)) {
    if (query[0] === '?') {
      query = (query as string).slice(1);
    }
    query = parse(query as string);
  }

  return Object.keys(query).reduce((res: object, key: string) => {
    if (
      query[key] != null &&
      query[key] !== '' &&
      validParams.indexOf(key) > -1
    ) {
      res[key] = query[key];
    }
    return res;
  }, {});
};

/**
 * Throws, if the query component contains duplicated keys
 * @throws InvalidRequestError
 */
export const validateQueryParams = (
  query: string | object,
  validParams: string[]
) => {
  query = sanitizeQueryParams(query, validParams);

  const paramKeys: string[] = Object.keys(query);
  const uniqueParamKeys = new Set(paramKeys);

  // it is also possible that koa,express will create an array of values when
  // parsing the qs
  // E.g from express docs : GET /shoes?color[]=blue&color[]=black&color[]=red
  // console.dir(req.query.color) => [blue, black, red]
  if (
    paramKeys.length !== uniqueParamKeys.size ||
    Object.values(query).some(val => Array.isArray(val))
  ) {
    throw new AuthorizationRequestErrors.InvalidRequestError(
      ERROR_DESCRIPTIONS.duplicate_query_parameter
    );
  }
};

export const validateMultipleRedirectUriParams = (query: Query) => {
  const redirectUriValue = query[PARAMETERS.REDIRECT_URI];
  const numOfRedirectUriParams = Object.keys(query).filter(
    key => key === PARAMETERS.REDIRECT_URI
  ).length;

  if (
    numOfRedirectUriParams > 1 ||
    (Array.isArray(redirectUriValue) && redirectUriValue.length > 1)
  ) {
    throw new AuthorizationRequestErrors.InvalidRequestError(
      ERROR_DESCRIPTIONS.duplicate_query_parameter
    );
  }
};

/**
 * Throws, if the provided value can not be found in a set of valid values
 * @throws InvalidRequestError
 */
export const validateParamValue = <T>(
  value: T,
  validValues: T[],
  errorDescription?: string
) => {
  if (!value || !validValues || validValues.indexOf(value) === -1) {
    throw new AuthorizationRequestErrors.InvalidRequestError(errorDescription);
  }
};

/**
 * ---------------------
 * Authorization Request
 * ---------------------
 */

/**
 * Atomic function to validate an authorization request.
 * Accepts {Request} which can be derived from an arbitrary req object
 * Requires a {findClientFn} to be able to find a Client
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
 */
export const authorizeRequest = async (
  req: Request,
  findClientFn: FindClientFunction,
  options?: Pick<AuthorizationServerOptions, 'development'>
): Promise<Partial<AuthorizationRequestMeta>> => {
  // Find & Validate Client. We must do this first, so that if any error happens
  // later we can decide whether we can redirect with the error or show an error
  // screen to the user
  let client: Client;

  const clientId: Client['clientId'] | undefined = _getSingleValue<
    Client['clientId']
  >(req.query[PARAMETERS.CLIENT_ID]);

  const redirectUri: Client['redirectUri'] | undefined = _getSingleValue<
    Client['redirectUri']
  >(req.query[PARAMETERS.REDIRECT_URI]);

  const state: string | undefined = _getSingleValue<string>(
    req.query[PARAMETERS.STATE]
  );

  // We need to do an excess check here to overcome open redirector attacks
  // It is possible for a hacker to tamper the request and add an additional
  // redirect_uri parameter at the end of the qs hoping that we will redirect
  // the code to that uri. In this case we must not redirect but raise a
  // clientError. We will do duplicate checks for other params too, later..
  try {
    validateMultipleRedirectUriParams(req.query);
  } catch (error) {
    const err: ErrorDTO = _getErrorDtoFromError(error);
    return {
      clientError: _onClientError(err),
    };
  }

  if (!clientId) {
    return {
      clientError: _onClientError({
        error: ERROR_CODES.invalid_request as ERROR_CODE,
        error_description: ERROR_DESCRIPTIONS.missing_client_id,
        state,
      }),
    };
  }

  try {
    client = await findClientFn(clientId, req);
  } catch (error) {
    return {
      clientError: _onClientError({
        error: ERROR_CODES.unauthorized_client as ERROR_CODE,
        error_description: ERROR_DESCRIPTIONS.invalid_client,
        state,
      }),
    };
  }

  const clientValidationError: ErrorDTO | void = validateClient(client, {
    clientId,
    redirectUri,
  } as ClientValidationMeta);

  if (clientValidationError) {
    return {
      clientError: _onClientError({ ...clientValidationError, state }),
    };
  }

  try {
    // the authorization request URI MUST NOT include a fragment component
    validateURIForFragment(req.uri);

    // require TLS
    if (!options?.development) {
      validateURIForTLS(req.uri);
    }

    // must support GET, may support POST
    validateURIHttpMethod(req.method);

    // response_type is mandatory
    const responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE = req.query[
      PARAMETERS.RESPONSE_TYPE
    ] as AUTHORIZATION_REQUEST_RESPONSE_TYPE;
    if (responseType == null) {
      throw new AuthorizationRequestErrors.InvalidRequestError(
        ERROR_DESCRIPTIONS.missing_response_type
      );
    }

    // grant type validation
    const grant = AUTHORIZATION_REQUEST_GRANTS[responseType];
    if (grant == null) {
      throw new AuthorizationRequestErrors.UnsupportedResponseTypeError(
        ERROR_DESCRIPTIONS.unsupported_response_type
      );
    }

    const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];

    // params MUST NOT be included more than once
    // koa and express removes the duplicates
    validateQueryParams(req.query, allowedParams);

    // checking mandatory params
    for (const mandatoryParam of grant.mandatoryParams) {
      if (req.query[mandatoryParam] == null) {
        throw new AuthorizationRequestErrors.InvalidRequestError();
      }
    }

    // Building the meta object
    const authorizationRequestMeta = {} as AuthorizationRequestMetaBase;

    for (const param of allowedParams) {
      if (req.query[param] != null) {
        authorizationRequestMeta[snakeCaseToCamelCase(param)] =
          req.query[param];
      }
    }

    // Validating code_challenge_method value
    if (authorizationRequestMeta.codeChallengeMethod) {
      validateParamValue<string>(
        authorizationRequestMeta.codeChallengeMethod.toLowerCase(),
        Object.keys(CODE_CHALLENGE_METHOD_TYPES),
        ERROR_DESCRIPTIONS.invalid_code_challenge_method
      );
    }

    // If there was no redirect_uri in the request we must use the one provided
    // at client registration
    if (!authorizationRequestMeta.redirectUri) {
      authorizationRequestMeta.redirectUri = client.redirectUri;
    }

    return { ...authorizationRequestMeta, client };
  } catch (error) {
    const errorDto: ErrorDTO = _getErrorDtoFromError(error);
    if (state) {
      errorDto.state = state;
    }
    return {
      error: errorDto,
      redirectUri: redirectUri ?? client.redirectUri,
    };
  }
};

/**
 * This is a middleware function to be used with an express like web framework
 * Internally uses the {authorizeRequest} helper but hooks into the framework
 * by calling the next middleware in case of a {clientError} or when there were
 * no errors. Redirects when {error} has been raised by {authorizeRequest}
 */
export const getAuthorizationRequestMiddleware = (
  findClientFn: FindClientFunction,
  options: AuthorizationServerOptions
) => async (req, res, next) => {
  const authorizationRequestMeta = await authorizeRequest(
    getRequest(req),
    findClientFn,
    options
  );

  if (__DEV__) {
    console.log('getAuthorizationRequestMiddleware => ', {
      ...authorizationRequestMeta,
    });
  }

  // When a client error happens we must not redirect the user automatically
  // to redirectUri because a clientError means either the client_id was
  // missing, or the redirect_uri was invalid or missing
  if (authorizationRequestMeta.clientError) {
    req.session.authorizationServer = {
      error: authorizationRequestMeta.clientError,
    } as AuthorizationRequestErrorMeta;

    next();
    return;
  }

  // When an error happen which is not a clientError we can redirect to the
  // redirect_uri with the error params
  if (authorizationRequestMeta.error) {
    res.redirect(
      `${authorizationRequestMeta.redirectUri}?${stringify({
        ...authorizationRequestMeta.error,
      })}`
    );
    return;
  }

  req.session.authorizationServer = {
    ...authorizationRequestMeta,
  } as AuthorizationRequestMeta;
  next();
};

/**
 * ---------------------
 *        Helpers
 * ---------------------
 */

const _onClientError = (errorDto: ErrorDTO) => {
  // Don't provide state if undefined. Later this object will be stringified
  // by nodejs's qs module which would append "&state=" which we don't want to
  if (errorDto.state == null) delete errorDto.state;
  return errorDto;
};

/**
 * If {error} is instance of AuthnzError then we parse special params from the
 * error object and construct an ErrorDTO as return value
 * Otherwise, we return a generic ErrorDTO
 */
const _getErrorDtoFromError = (error: AuthnzError | Error): ErrorDTO => {
  if (error instanceof AuthnzError) {
    return {
      error: error.code,
      error_description: error.description,
    };
  }
  return {
    error: ERROR_CODES.server_error as ERROR_CODE,
    error_description: 'unidentified error',
  };
};

const _getSingleValue = <T>(value: T | T[]): T => {
  if (Array.isArray(value)) {
    return value[value.length - 1];
  }
  return value;
};
