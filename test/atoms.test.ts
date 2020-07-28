import * as atoms from '../src/atoms';
import { AuthorizationRequest } from '../src/errors';

describe('validateURIForFragment', () => {
  it("throws if can't parse uri string to an URL", () => {
    expect(() =>
      atoms.validateURIForFragment('this is not a valid uri')
    ).toThrow(AuthorizationRequest.InvalidRequestError);
  });
  it('throws if uri string contains a hash fragment', () => {
    expect(() =>
      atoms.validateURIForFragment('http://website.com/path#frag')
    ).toThrow(AuthorizationRequest.InvalidRequestError);
  });
  it('succeeds', () => {
    expect(() =>
      atoms.validateURIForFragment('http://website.com/path?lang=en')
    ).not.toThrow();
  });
});

describe('validateURIForTLS', () => {
  it("throws if can't parse uri string to an URL", () => {
    expect(() => atoms.validateURIForTLS('this is not a valid uri')).toThrow(
      AuthorizationRequest.InvalidRequestError
    );
  });
  it("throws if uri's protocol is not https", () => {
    expect(() => atoms.validateURIForTLS('http://website.com/path')).toThrow(
      AuthorizationRequest.InvalidRequestError
    );
  });
  it('succeeds', () => {
    expect(() =>
      atoms.validateURIForTLS('https://website.com/path?lang=en')
    ).not.toThrow();
  });
});

describe('validateURIHttpMethod', () => {
  it('throws if method is not defined', () => {
    expect(atoms.validateURIHttpMethod).toThrow(
      AuthorizationRequest.InvalidRequestError
    );
  });
  it('throws if method is not POST or GET', () => {
    ['PUT', 'PATCH', 'DELETE', 'OPTIONS', 'invalid'].forEach(method => {
      expect(() => atoms.validateURIHttpMethod(method)).toThrow(
        AuthorizationRequest.InvalidRequestError
      );
    });
  });
  it('succeeds', () => {
    expect(() => atoms.validateURIHttpMethod('POST')).not.toThrow();
    expect(() => atoms.validateURIHttpMethod('GET')).not.toThrow();
  });
});

describe('sanitizeQueryParams', () => {
  const validParams = ['lang', 'scope'];
  it('works for query objects. express/koa like', () => {
    expect(
      atoms.sanitizeQueryParams(
        { scope: '', lang: 'en', invalid: 'zzz' },
        validParams
      )
    ).toEqual({
      lang: 'en',
    });
  });
  it('works for queryStrings', () => {
    expect(
      atoms.sanitizeQueryParams('?lang=en&scope&invalid=zzz', validParams)
    ).toEqual({
      lang: 'en',
    });
    expect(
      atoms.sanitizeQueryParams('lang=en&scope=&invalid=zzz', validParams)
    ).toEqual({
      lang: 'en',
    });
  });
});

describe('validateQueryParams', () => {
  const validParams = ['lang', 'scope'];
  it('throws if there are duplicated query parameters', () => {
    expect(() =>
      atoms.validateQueryParams('?lang=en&lang=hu&scope&invalid', validParams)
    ).toThrow(AuthorizationRequest.InvalidRequestError);
  });
  it('throws if there are express/koa queryParser like arrays', () => {
    expect(() =>
      atoms.validateQueryParams({ lang: ['en', 'hu'] }, validParams)
    ).toThrow(AuthorizationRequest.InvalidRequestError);
  });
  it('good case', () => {
    expect(() =>
      atoms.validateQueryParams('lang=en&scope=', validParams)
    ).not.toThrow();
  });
});
