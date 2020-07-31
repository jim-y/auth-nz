import {
  FindClientFunction,
  FindAuthorizationCodeFunction,
  Request,
} from './types';

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

// Based on my own kata @codewars
// @see https://www.codewars.com/kata/541a077539c5ef3fd8001133
export const typer = (function(toString) {
  return {
    isString: function(obj) {
      return toString.call(obj) === '[object String]';
    },
    isFunction: function(obj) {
      return toString.call(obj) === '[object Function]';
    },
    isDate: function(obj) {
      return toString.call(obj) === '[object Date]';
    },
    isRegExp: function(obj) {
      return toString.call(obj) === '[object RegExp]';
    },
    isBoolean: function(obj) {
      return toString.call(obj) === '[object Boolean]';
    },
    isError: function(obj) {
      return toString.call(obj) === '[object Error]';
    },
    isNumber: function(obj) {
      return toString.call(obj) === '[object Number]' && !isNaN(obj);
    },
    isArray: function(obj) {
      return Array.isArray
        ? Array.isArray(obj)
        : toString.call(obj) === '[object Array]';
    },
    isNull: function(obj) {
      return obj === null;
    },
    isUndefined: function(obj) {
      return obj === void 0;
    },
  };
})(Object.prototype.toString);

export const getRequest = (req): Request => {
  // express
  return {
    query: req.query,
    uri: `${req.protocol}://${req.host}${
      req.originalUrl ? `/${req.originalUrl}` : ''
    }`,
    method: req.method,
  } as Request;
  // koa - tbd
};
