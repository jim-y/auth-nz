import { stringify } from 'querystring';
import { PARAMETERS, AUTHORIZATION_REQUEST_GRANTS } from './constants';
import {
  AUTHORIZATION_REQUEST_RESPONSE_TYPE,
  Client,
  FindClientFunction,
  AuthorizationRequestMeta,
  ClientValidationMeta,
  AuthorizationRequestMetaBase,
  AuthorizationServerOptions,
} from './types';
import { snakeCaseToCamelCase } from './utils';
import {
  validateClient,
  validateURIForFragment,
  validateURIForTLS,
  validateURIHttpMethod,
  validateQueryParams,
} from './atoms';

export const getValidateAuthorizationRequestMiddleware = (
  findClientFn: FindClientFunction,
  options: AuthorizationServerOptions
) => async (req, res, next) => {
  const urlString = `${req.protocol}://${req.host}${
    req.originalUrl ? `/${req.originalUrl}` : ''
  }`;
  // 1) the authorization request URI MUST NOT include a fragment component
  validateURIForFragment(urlString);
  // 2) require TLS
  if (!options.development) {
    validateURIForTLS(urlString);
  }
  // 3) must support GET may support POST
  validateURIHttpMethod(urlString);

  // 4) response_type is mandatory
  const responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE =
    req.query[PARAMETERS.RESPONSE_TYPE];
  if (responseType == null) {
    throw new Error('response_type parameter is required');
  }

  // 5) finding out the grant type
  const grant = AUTHORIZATION_REQUEST_GRANTS[responseType];
  if (grant == null) {
    throw new Error(
      'Unsupported grant type. response_type must be either "code" or "token".'
    );
  }

  const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];

  // 6) params MUST NOT be included more than once
  // koa and express removes the duplicates
  validateQueryParams(req.query, allowedParams);

  // 7) Checking mandatory params
  for (const mandatoryParam of grant.mandatoryParams) {
    if (req.query[mandatoryParam] == null) {
      throw new Error(
        `Required parameter "${mandatoryParam}" is missing from the authorization request`
      );
    }
  }

  // Building the meta object
  const authorizationRequestMeta = {} as AuthorizationRequestMetaBase;

  for (const param of allowedParams) {
    if (req.query[param] != null) {
      authorizationRequestMeta[snakeCaseToCamelCase(param)] = req.query[param];
    }
  }

  // TODO: additional validations, like CODE_CHALLENGE_METHOD values etc..

  // TODO catch error
  const client: Client = await findClientFn(
    authorizationRequestMeta.clientId,
    req
  );

  // 8) Client validation
  validateClient(client, {
    clientId: authorizationRequestMeta.clientId,
    redirectUri: authorizationRequestMeta.redirectUri,
  } as ClientValidationMeta);

  // 9) Error handling short circuit
  // return res.redirect(`${client.redirectUri}?${stringify({})}`);

  req.session.authorizationServer = {
    ...authorizationRequestMeta,
    client,
  } as AuthorizationRequestMeta;

  next();
};
