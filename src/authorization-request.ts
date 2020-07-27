import { PARAMETERS, AUTHORIZATION_REQUEST_GRANTS } from './constants';
import {
  AUTHORIZATION_REQUEST_RESPONSE_TYPE,
  Client,
  FindClientFunction,
  AuthorizationRequestMeta,
  ClientValidationMeta,
  AuthorizationRequestMetaBase,
} from './types';
import { snakeCaseToCamelCase } from './utils';
import { validateClient } from './atoms';

export const getValidateAuthorizationRequestMiddleware = (
  findClientFn: FindClientFunction
) => async (req, _res, next) => {
  console.log('validateAuthorizationRequest', req.query);

  // 1) the authorization request URI MUST NOT include a fragment component
  const url = /* koa, express */ new URL(
    `${req.protocol}://${req.host}${
      req.originalUrl ? `/${req.originalUrl}` : ''
    }`
  );
  if (url.hash != null && url.hash !== '') {
    throw new Error('The request must not contain an URI fragment');
  }

  // 2) require TLS
  if (process.env.NODE_ENV === 'production' && url.protocol !== 'https') {
    throw new Error('The request must use TLS');
  }

  // 3) must support GET may support POST
  if (
    req.method.toLowerCase() !== 'get' &&
    req.method.toLowerCase() !== 'post'
  ) {
    throw new Error('Unsupported method type. Only GET and POST are allowed');
  }

  // 4) params MUST NOT be included more than once
  // koa and express removes the duplicates
  const paramKeys = Object.keys(req.query);
  const uniqueParamKeys = new Set(paramKeys);
  if (paramKeys.length !== uniqueParamKeys.size) {
    throw new Error('Every parameter must appear only once');
  }
  // it is also possible that koa,express will create an array of values when parsing the qs
  // E.g from express docs : GET /shoes?color[]=blue&color[]=black&color[]=red
  // console.dir(req.query.color) => [blue, black, red]
  if (Object.values(req.query).some(val => Array.isArray(val))) {
    throw new Error('Every parameter must appear only once');
  }

  // 5) response_type is mandatory
  const responseType: AUTHORIZATION_REQUEST_RESPONSE_TYPE =
    req.query[PARAMETERS.RESPONSE_TYPE];
  if (responseType == null) {
    throw new Error('response_type parameter is required');
  }

  // 6) finding out the grant type
  const grant = AUTHORIZATION_REQUEST_GRANTS[responseType];
  if (grant == null) {
    throw new Error(
      'Unsupported grant type. response_type must be either "code" or "token".'
    );
  }

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
  const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];
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

  req.session.authorizationServer = {
    ...authorizationRequestMeta,
    client,
  } as AuthorizationRequestMeta;

  next();
};
