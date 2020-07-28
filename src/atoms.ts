import { ValidateClientFunction, Client, ClientValidationMeta } from './types';
import { AuthorizationRequest } from './errors';
import { typer } from './utils';
import { parse } from 'querystring';

export const validateClient: ValidateClientFunction = (
  client: Client,
  meta: Partial<ClientValidationMeta>
): void => {
  if (client == null) throw new Error('Unregistered client');
  if (client.clientId !== meta.clientId)
    throw new Error('Client authentication failed. Invalid Client ID!');
  // TODO check base path instead of equality
  if (meta.redirectUri && client.redirectUri !== meta.redirectUri)
    throw new Error(
      'Client authentication failed. Invalid Client redirection_uri!'
    );

  if (meta.clientSecret && client.clientSecret !== meta.clientSecret) {
    throw new Error('Client authentication failed. Invalid Client secret!');
  }
};

export const validateURIForFragment = (uri: string) => {
  let url;

  try {
    url = new URL(uri);
  } catch (error) {
    throw new AuthorizationRequest.InvalidRequestError();
  }

  if (url.hash != null && url.hash !== '') {
    throw new AuthorizationRequest.InvalidRequestError();
  }
};

export const validateURIForTLS = (uri: string) => {
  let url;

  try {
    url = new URL(uri);
  } catch (error) {
    throw new AuthorizationRequest.InvalidRequestError();
  }

  if (url.protocol !== 'https:') {
    throw new AuthorizationRequest.InvalidRequestError();
  }
};

export const validateURIHttpMethod = (method: string) => {
  if (
    !method ||
    (method?.toLowerCase() !== 'get' && method?.toLowerCase() !== 'post')
  ) {
    throw new AuthorizationRequest.InvalidRequestError();
  }
};

// rfc6749#3.1: parameters sent without a value MUST be treated  as if they
// were omitted from the request. The authorization server MUST ignore
// unrecognized request parameters
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

export const validateQueryParams = (
  query: string | object,
  validParams: string[]
) => {
  query = sanitizeQueryParams(query, validParams);

  const paramKeys: string[] = Object.keys(query);
  const uniqueParamKeys = new Set(paramKeys);

  if (paramKeys.length !== uniqueParamKeys.size) {
    throw new AuthorizationRequest.InvalidRequestError();
  }

  // it is also possible that koa,express will create an array of values when
  // parsing the qs
  // E.g from express docs : GET /shoes?color[]=blue&color[]=black&color[]=red
  // console.dir(req.query.color) => [blue, black, red]
  if (Object.values(query).some(val => Array.isArray(val))) {
    throw new AuthorizationRequest.InvalidRequestError();
  }
};
