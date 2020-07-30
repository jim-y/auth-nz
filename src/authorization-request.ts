import { stringify } from 'querystring';
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
} from './types';
import { snakeCaseToCamelCase } from './utils';
import {
  validateClient,
  validateURIForFragment,
  validateURIForTLS,
  validateURIHttpMethod,
  validateQueryParams,
  validateParamValue,
  getErrorDtoFromError,
} from './atoms';
import { AuthorizationRequest, ERROR_CODES } from './errors';

export const getValidateAuthorizationRequestMiddleware = (
  findClientFn: FindClientFunction,
  options: AuthorizationServerOptions
) => async (req, res, next) => {
  // Find & Validate Client. We must do this first, so that if any error happens
  // later we can decide whether we can redirect with the error or show an error
  // screen to the user
  let client: Client;
  let errorDto: ErrorDTO | void;
  const clientId: Client['clientId'] = req.query[PARAMETERS.CLIENT_ID];
  const redirectUri: Client['redirectUri'] = req.query[PARAMETERS.REDIRECT_URI];
  const state: string = req.query[PARAMETERS.STATE];

  if (!clientId) {
    return _onClientError(
      {
        error: ERROR_CODES.invalid_request as ERROR_CODE,
        error_description: 'client_id missing',
        state,
      },
      req,
      next
    );
  }

  try {
    client = await findClientFn(clientId, req);
  } catch (error) {
    return _onClientError(
      {
        error: ERROR_CODES.unauthorized_client as ERROR_CODE,
        error_description: 'invalid client',
        state,
      },
      req,
      next
    );
  }

  errorDto = validateClient(client, {
    clientId,
    redirectUri,
  } as ClientValidationMeta);

  if (errorDto) {
    return _onClientError({ ...errorDto, state }, req, next);
  }

  const urlString = `${req.protocol}://${req.host}${
    req.originalUrl ? `/${req.originalUrl}` : ''
  }`;

  try {
    // the authorization request URI MUST NOT include a fragment component
    validateURIForFragment(urlString);

    // require TLS
    if (!options.development) {
      validateURIForTLS(urlString);
    }
    // must support GET, may support POST
    validateURIHttpMethod(req.method);

    // response_type is mandatory
    const responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE =
      req.query[PARAMETERS.RESPONSE_TYPE];
    if (responseType == null) {
      throw new AuthorizationRequest.InvalidRequestError(
        'response_type is mandatory'
      );
    }

    // grant type validation
    const grant = AUTHORIZATION_REQUEST_GRANTS[responseType];
    if (grant == null) {
      throw new AuthorizationRequest.UnsupportedResponseTypeError(
        'unsupported response_type'
      );
    }

    const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];

    // params MUST NOT be included more than once
    // koa and express removes the duplicates
    validateQueryParams(req.query, allowedParams);

    // checking mandatory params
    for (const mandatoryParam of grant.mandatoryParams) {
      if (req.query[mandatoryParam] == null) {
        throw new AuthorizationRequest.InvalidRequestError();
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
        'pkce code_challenge_method transform algorithm not supported'
      );
    }

    req.session.authorizationServer = {
      ...authorizationRequestMeta,
      client,
    } as AuthorizationRequestMeta;

    next();
  } catch (error) {
    const errorDto: ErrorDTO = getErrorDtoFromError(error);
    if (state) {
      errorDto.state = state;
    }
    res.redirect(`${client.redirectUri}?${stringify({ ...errorDto })}`);
    return;
  }
};

// When a client error happens we must not redirect the user automatically
// to redirectUri
const _onClientError = (errorDto: ErrorDTO, req, next) => {
  // Don't provide state if undefined. Later this object will be stringified
  // by nodejs's qs module which would append "&state=" which we don't want to
  if (errorDto.state == null) delete errorDto.state;

  req.session.authorizationServer = {
    error: errorDto,
  } as AuthorizationRequestErrorMeta;

  next();
};
