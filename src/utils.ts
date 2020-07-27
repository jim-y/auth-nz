import { FindClientFunction, FindAuthorizationCodeFunction } from './types';

// Credit: https://hisk.io/javascript-snake-to-camel/
export const snakeCaseToCamelCase = str =>
  str.replace(/([-_][a-z])/g, group =>
    group
      .toUpperCase()
      .replace('-', '')
      .replace('_', '')
  );

export const getFindClientFn = (
  findClientFn?: FindClientFunction,
  findClient?: FindClientFunction
): FindClientFunction | void => {
  if (!findClientFn && !findClient) {
    throw new Error(
      'You must either provide a cb to this function to fetch a client or provide one in AuthorizationServerOptions'
    );
  }
  return findClientFn ?? findClient;
};

export const getFindAuthorizationCodeFn = (
  findAuthorizationCodeFn: FindAuthorizationCodeFunction,
  findAuthorizationCode: FindAuthorizationCodeFunction
) => {
  if (!findAuthorizationCodeFn && !findAuthorizationCode) {
    throw new Error(
      'You must either provide a cb to this function as second parameter to fetch an authorization code or provide one in AuthorizationServerOptions'
    );
  }
  return findAuthorizationCodeFn ?? findAuthorizationCode;
};
