import {
  ValidateClientFunction,
  Client,
  ClientValidationMeta,
  ErrorDTO,
  ERROR_CODE,
} from './types';
import { AuthorizationRequest, ERROR_CODES, AuthnzError } from './errors';
import { typer } from './utils';
import { parse } from 'querystring';

export const validateClient: ValidateClientFunction = (
  client: Client,
  meta: Partial<ClientValidationMeta>
): ErrorDTO | void => {
  if (client == null) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'unregistered client',
    };
  }

  if (client.clientId !== meta.clientId) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'invalid client_id',
    };
  }

  // TODO check base path instead of equality
  if (meta.redirectUri && client.redirectUri !== meta.redirectUri) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'invalid redirection_uri',
    };
  }

  if (!meta.redirectUri && !client.redirectUri) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'missing redirection_uri',
    };
  }

  if (meta.clientSecret && client.clientSecret !== meta.clientSecret) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'invalid client_secret',
    };
  }
};

export const validateURIForFragment = (uri: string) => {
  let url;

  try {
    url = new URL(uri);
  } catch (error) {
    throw new AuthorizationRequest.InvalidRequestError('malformed url');
  }

  if (url.hash != null && url.hash !== '') {
    throw new AuthorizationRequest.InvalidRequestError(
      'the request must not contain a url fragment'
    );
  }
};

export const validateURIForTLS = (uri: string) => {
  let url;

  try {
    url = new URL(uri);
  } catch (error) {
    throw new AuthorizationRequest.InvalidRequestError('malformed url');
  }

  if (url.protocol !== 'https:') {
    throw new AuthorizationRequest.InvalidRequestError('must use TLS');
  }
};

export const validateURIHttpMethod = (method: string) => {
  if (
    !method ||
    (method?.toLowerCase() !== 'get' && method?.toLowerCase() !== 'post')
  ) {
    throw new AuthorizationRequest.InvalidRequestError(
      'only http get and post are supported'
    );
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

  // it is also possible that koa,express will create an array of values when
  // parsing the qs
  // E.g from express docs : GET /shoes?color[]=blue&color[]=black&color[]=red
  // console.dir(req.query.color) => [blue, black, red]
  if (
    paramKeys.length !== uniqueParamKeys.size ||
    Object.values(query).some(val => Array.isArray(val))
  ) {
    throw new AuthorizationRequest.InvalidRequestError(
      'duplicated query parameter'
    );
  }
};

export const validateParamValue = <T>(
  value: T,
  validValues: T[],
  errorDescription?: string
) => {
  if (validValues.indexOf(value) === -1) {
    throw new AuthorizationRequest.InvalidRequestError(errorDescription);
  }
};

export const getErrorDtoFromError = (error: AuthnzError | Error): ErrorDTO => {
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
