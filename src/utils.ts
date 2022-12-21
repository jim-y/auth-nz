import { Query } from './types';
import { parse } from 'querystring';

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
export const ensureFunction = <F>(callbackFn: F, fromOptionsFn: F, errorMsg: string): F => {
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
            return Array.isArray ? Array.isArray(obj) : toString.call(obj) === '[object Array]';
        },
        isNull: function(obj) {
            return obj === null;
        },
        isUndefined: function(obj) {
            return obj === void 0;
        },
    };
})(Object.prototype.toString);

/**
 * rfc6749#3.1: parameters sent without a value MUST be treated  as if they
 * were omitted from the request. The authorization server MUST ignore
 * unrecognized request parameters
 */
export const sanitizeQueryParams = (query: string | object, validParams: string[]) => {
    query = parseQuery(query);

    return Object.keys(query).reduce((res: object, key: string) => {
        if (query[key] != null && query[key] !== '' && validParams.indexOf(key) > -1) {
            res[key] = query[key];
        }
        return res;
    }, {});
};

/**
 * rfc6749#3.2: parameters sent without a value MUST be treated  as if they
 * were omitted from the request. The authorization server MUST ignore
 * unrecognized request parameters
 */
export const sanitizeBodyParams = (body: object, validParams: string[]) => {
    return Object.keys(body).reduce((res: object, key: string) => {
        if (body[key] != null && body[key] !== '' && validParams.indexOf(key) > -1) {
            res[key] = body[key];
        }
        return res;
    }, {});
};

export const parseQuery = (query: string | object): Query => {
    if (typer.isString(query)) {
        if (query[0] === '?') {
            query = (query as string).slice(1);
        }
        query = parse(query as string);
    }
    return query as Query;
};

export const getBody = (req: { body: any }): object => req.body;
export const getQuery = (req: { query: Query }): Query => parseQuery(req.query);
export const getUri = (req: { uri?: string; url?: string }) => req.uri ?? req.url;
export const getMethod = (req: { method: string }) => req.method;
