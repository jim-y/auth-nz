import {
  validateParamValue,
  validateQueryParams,
  validateURIForFragment,
  validateURIForTLS,
  validateURIHttpMethod,
  sanitizeQueryParams,
} from '../src/authorization-request';
import { InvalidRequestError } from '../src/errors';

describe('validateURIForFragment', () => {
  it("throws if can't parse uri string to an URL", () => {
    expect(() => validateURIForFragment('this is not a valid uri')).toThrow(
      InvalidRequestError
    );
  });
  it('throws if uri string contains a hash fragment', () => {
    expect(() =>
      validateURIForFragment('http://website.com/path#frag')
    ).toThrow(InvalidRequestError);
  });
  it('succeeds', () => {
    expect(() =>
      validateURIForFragment('http://website.com/path?lang=en')
    ).not.toThrow();
  });
});

describe('validateURIForTLS', () => {
  it("throws if can't parse uri string to an URL", () => {
    expect(() => validateURIForTLS('this is not a valid uri')).toThrow(
      InvalidRequestError
    );
  });
  it("throws if uri's protocol is not https", () => {
    expect(() => validateURIForTLS('http://website.com/path')).toThrow(
      InvalidRequestError
    );
  });
  it('succeeds', () => {
    expect(() =>
      validateURIForTLS('https://website.com/path?lang=en')
    ).not.toThrow();
  });
});

describe('validateURIHttpMethod', () => {
  it('throws if method is not defined', () => {
    expect(validateURIHttpMethod).toThrow(InvalidRequestError);
  });
  it('throws if method is not POST or GET', () => {
    ['PUT', 'PATCH', 'DELETE', 'OPTIONS', 'invalid'].forEach(method => {
      expect(() => validateURIHttpMethod(method)).toThrow(InvalidRequestError);
    });
  });
  it('succeeds', () => {
    expect(() => validateURIHttpMethod('POST')).not.toThrow();
    expect(() => validateURIHttpMethod('GET')).not.toThrow();
  });
});

describe('sanitizeQueryParams', () => {
  const validParams = ['lang', 'scope'];
  it('works for query objects. express/koa like', () => {
    expect(
      sanitizeQueryParams(
        { scope: '', lang: 'en', invalid: 'zzz' },
        validParams
      )
    ).toEqual({
      lang: 'en',
    });
  });
  it('works for queryStrings', () => {
    expect(
      sanitizeQueryParams('?lang=en&scope&invalid=zzz', validParams)
    ).toEqual({
      lang: 'en',
    });
    expect(
      sanitizeQueryParams('lang=en&scope=&invalid=zzz', validParams)
    ).toEqual({
      lang: 'en',
    });
  });
});

describe('validateQueryParams', () => {
  const validParams = ['lang', 'scope'];
  it('throws if there are duplicated query parameters', () => {
    expect(() =>
      validateQueryParams('?lang=en&lang=hu&scope&invalid', validParams)
    ).toThrow(InvalidRequestError);
  });
  it('throws if there are express/koa queryParser like arrays', () => {
    expect(() =>
      validateQueryParams({ lang: ['en', 'hu'] }, validParams)
    ).toThrow(InvalidRequestError);
  });
  it('good case', () => {
    expect(() =>
      validateQueryParams('lang=en&scope=', validParams)
    ).not.toThrow();
  });
});

describe('validateParamValue', () => {
  it('throws on missing params', () => {
    expect(validateParamValue).toThrow(InvalidRequestError);
    expect(() => validateParamValue(undefined, ['valid'])).toThrow(
      InvalidRequestError
    );
    expect(() => validateParamValue('test', undefined)).toThrow(
      InvalidRequestError
    );
  });
  it('throws if value is not present in validValues', () => {
    expect(() =>
      validateParamValue<string>('test', ['valid', 'value'])
    ).toThrow(InvalidRequestError);
  });
});
