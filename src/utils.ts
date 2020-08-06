import { Request, AuthorizationServerOptions } from './types';

// Credit: https://hisk.io/javascript-snake-to-camel/
export const snakeCaseToCamelCase = str =>
  str.replace(/([-_][a-z])/g, group =>
    group
      .toUpperCase()
      .replace('-', '')
      .replace('_', '')
  );

// Get a <F> function either from params or from
// AuthorizationServerOptions or throw if none
export const ensureFunction = <F>(
  callbackFn: F,
  fromOptionsFn: F,
  errorMsg: string
): F => {
  if (!callbackFn && !fromOptionsFn) {
    throw new Error(errorMsg);
  }
  return callbackFn ?? fromOptionsFn;
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

export const getRequest = (
  req,
  options?: AuthorizationServerOptions
): Request => {
  // express, nest
  return {
    query: req.query,
    uri: `${req.protocol}://${req.host}${
      req.originalUrl ? `/${req.originalUrl}` : ''
    }`,
    method: req.method,
    session: options ? req[options.sessionProperty] : {},
  } as Request;
  // koa - tbd
};
