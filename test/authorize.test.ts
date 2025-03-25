import * as cookie from 'cookie';
import { createService } from '../src/core.ts';
import { suite, test, beforeEach, mock } from 'node:test';
import assert from 'node:assert';
import type { AuthNZOptions, AuthNZService } from '../src/types/index.ts';
import { handleRoute } from '../src/oidc/route.ts';
import { ERROR_CODES, ERROR_DESCRIPTIONS } from '../src/errors.ts';
import { AUTHORIZATION_REQUEST_GRANTS, OIDC_PARAMS, RESPONSE_TYPES } from '../src/constants.ts';

void suite('authorize request validation', () => {
    let underTest: AuthNZService;
    let options: AuthNZOptions;
    let redirectURI: string;
    beforeEach(() => {
        underTest = createService({
            base: 'http://localhost:8080',
            clients: [
                {
                    client_id: 'foo',
                    client_secret: 'bar',
                    redirect_uris: ['http://localhost:3000/api/callback'],
                    grant_types: ['authorization_code']
                }
            ],
            getUser: async () => null
        });
        options = underTest.options;
        redirectURI = options.clients[0].redirect_uris[0];
    });

    test('duplicated query params validation', async () => {
        const grant = AUTHORIZATION_REQUEST_GRANTS[RESPONSE_TYPES.code];
        const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];
        for (const p of allowedParams) {
            let value = 'foo';
            const request = new Request(`http://localhost:8080/api/oidc/authorize?${p}=${value}&${p}=${value}`, {
                method: 'GET'
            });
            const response = await handleRoute(request, request, options);
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(
                locationUrl.searchParams.get('error_description'),
                ERROR_DESCRIPTIONS.duplicate_query_parameter
            );
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.invalid_request);
        }
    });

    test('fragment component validation', async () => {
        const request = new Request(`http://localhost:8080/api/oidc/authorize#frag`, {
            method: 'GET'
        });
        const response = await handleRoute(request, request, options);
        assert.equal(response.status, 302);
        const locationStr = response.headers.get('location');
        const locationUrl = new URL(locationStr);
        assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.url_fragment);
        assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.invalid_request);
    });

    test('invalid http method validation', async () => {
        for (const method of ['PUT', 'PATCH', 'OPTIONS', 'DELETE']) {
            const request = new Request(`http://localhost:8080/api/oidc/authorize`, { method });
            const response = await handleRoute(request, request, options);
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.invalid_http_method);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.invalid_request);
        }
    });

    void suite('mandatory params validation', () => {
        test('missing response_type', async () => {
            const url = new URL('http://localhost:8080/api/oidc/authorize');
            const request = new Request(url, { method: 'get' });
            const response = await handleRoute(request, request, options);
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.missing_response_type);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.invalid_request);
        });
        test('missing client_id', async () => {
            const url = new URL('http://localhost:8080/api/oidc/authorize');
            url.searchParams.set('response_type', 'code');
            const request = new Request(url, { method: 'get' });
            const response = await handleRoute(request, request, options);
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.missing_client_id);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.invalid_request);
        });
        test('missing redirect_uri', async () => {
            const url = new URL('http://localhost:8080/api/oidc/authorize');
            url.searchParams.set('response_type', 'code');
            url.searchParams.set('client_id', 'foo');
            const request = new Request(url, { method: 'get' });
            const response = await handleRoute(request, request, options);
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.missing_redirect_uri);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.invalid_request);
        });
        test('invalid redirect_uri', async () => {
            const url = new URL('http://localhost:8080/api/oidc/authorize');
            url.searchParams.set('response_type', 'code');
            url.searchParams.set('client_id', 'foo');
            url.searchParams.set('redirect_uri', 'baz');
            const request = new Request(url, { method: 'get' });
            const response = await handleRoute(request, request, options);
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.invalid_redirect_uri);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.invalid_request);
        });
    });

    test('unsupported response_type validation', async () => {
        const request = new Request(`http://localhost:8080/api/oidc/authorize?response_type=notcode`, {
            method: 'get'
        });
        const response = await handleRoute(request, request, options);
        assert.equal(response.status, 302);
        const locationStr = response.headers.get('location');
        const locationUrl = new URL(locationStr);
        assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.unsupported_response_type);
        assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.unsupported_response_type);
    });

    void suite('client validation', () => {
        test('unregistered client', async () => {
            const url = new URL('http://localhost:8080/api/oidc/authorize');
            url.searchParams.set('response_type', 'code');
            url.searchParams.set('client_id', 'baz');
            url.searchParams.set('redirect_uri', redirectURI);
            const request = new Request(url, { method: 'get' });
            options.getClient = async () => null;
            const response = await handleRoute(request, request, options);
            delete options.getClient;
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.unregistered_client);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.unauthorized_client);
        });
        test('client_id mismatch', async () => {
            const url = new URL('http://localhost:8080/api/oidc/authorize');
            url.searchParams.set('response_type', 'code');
            url.searchParams.set('client_id', 'baz');
            url.searchParams.set('redirect_uri', redirectURI);
            const request = new Request(url, { method: 'get' });
            options.getClient = async () => ({
                client_id: 'bar',
                client_secret: 'bar',
                redirect_uris: ['http://localhost:9000/api/oidc/cb'],
                grant_types: ['authorization_code']
            });
            const response = await handleRoute(request, request, options);
            delete options.getClient;
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.client_id_mismatch);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.unauthorized_client);
        });
        test('redirect_uri mismatch', async () => {
            const url = new URL('http://localhost:8080/api/oidc/authorize');
            url.searchParams.set('response_type', 'code');
            url.searchParams.set('client_id', 'foo');
            url.searchParams.set('redirect_uri', `${redirectURI}/cb`);
            const request = new Request(url, { method: 'get' });
            const response = await handleRoute(request, request, options);
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.redirect_uri_mismatch);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.unauthorized_client);
        });
        test('invalid grant_type -- compared to defaultScopes', async () => {
            const url = new URL('http://localhost:8080/api/oidc/authorize');
            url.searchParams.set('response_type', 'code');
            url.searchParams.set('client_id', 'foo');
            url.searchParams.set('redirect_uri', options.clients[0].redirect_uris[0]);
            url.searchParams.set('scope', 'openid email profile address phone api:read api:write');
            const request = new Request(url, { method: 'get' });
            const response = await handleRoute(request, request, options);
            assert.equal(response.status, 302);
            const locationStr = response.headers.get('location');
            const locationUrl = new URL(locationStr);
            assert.equal(locationUrl.searchParams.get('error_description'), ERROR_DESCRIPTIONS.invalid_scope);
            assert.equal(locationUrl.searchParams.get('error'), ERROR_CODES.invalid_scope);
        });
    });
});

void suite('authorize', () => {
    let underTest: AuthNZService;
    let options: AuthNZOptions;
    let mockGetUser;
    beforeEach(() => {
        mockGetUser = mock.fn(() => Promise.resolve(null));
        underTest = createService({
            base: 'http://localhost:8080',
            clients: [
                {
                    client_id: 'foo',
                    client_secret: 'bar',
                    redirect_uris: ['http://localhost:3000/api/callback'],
                    grant_types: ['authorization_code']
                }
            ],
            getUser: mockGetUser
        });
        options = underTest.options;
    });

    test('valid request but user is unauthenticated', async () => {
        const url = new URL('http://localhost:8080/api/oidc/authorize');
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('client_id', 'foo');
        url.searchParams.set('redirect_uri', 'http://localhost:3000/api/callback');
        const request = new Request(url, { method: 'get' });
        const response = await handleRoute(request, request, options);
        assert.equal(response.status, 302);

        const cookieStr = response.headers.get('set-cookie');
        const setCookie = cookie.parse(cookieStr);
        assert.ok(cookieStr);
        assert.ok(setCookie['authnz:step:login']);

        const locationStr = response.headers.get('location');
        const signInUrl = new URL(locationStr);
        assert.ok(signInUrl.href.includes(options.signInURL.pathname));
        assert.ok(
            String(signInUrl.searchParams.get('redirectTo')).includes(
                `/api/oidc/step/${setCookie['authnz:step:login']}/login`
            )
        );
    });

    test('valid request, user is authenticated, need consent', async () => {
        const url = new URL('http://localhost:8080/api/oidc/authorize');
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('client_id', 'foo');
        url.searchParams.set('redirect_uri', 'http://localhost:3000/api/callback');
        const request = new Request(url, { method: 'get' });
        mockGetUser.mock.mockImplementationOnce(() =>
            Promise.resolve({
                sub: '123',
                email: 'test@example.com'
            })
        );
        const response = await handleRoute(request, request, options);
        assert.equal(response.status, 302);
        assert.equal(mockGetUser.mock.callCount(), 1);

        const cookieStr = response.headers.get('set-cookie');
        const setCookie = cookie.parse(cookieStr);
        assert.ok(cookieStr);
        assert.ok(setCookie['authnz:step:consent']);

        const locationStr = response.headers.get('location');
        const signInUrl = new URL(locationStr);
        assert.ok(signInUrl.href.includes(options.consentURL.pathname));
        assert.ok(
            String(signInUrl.searchParams.get('redirectTo')).includes(
                `/api/oidc/step/${setCookie['authnz:step:consent']}/decision`
            )
        );
    });

    test('trusted client, no need for consent', async () => {
        const url = new URL('http://localhost:8080/api/oidc/authorize');
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('client_id', 'foo');
        url.searchParams.set('redirect_uri', 'http://localhost:3000/api/callback');
        const request = new Request(url, { method: 'get' });
        mockGetUser.mock.mockImplementationOnce(() =>
            Promise.resolve({
                sub: '123',
                email: 'test@example.com'
            })
        );
        options.clients[0].trusted = true;
        const response = await handleRoute(request, request, options);
        options.clients[0].trusted = false;
        assert.equal(response.status, 302);
        assert.equal(mockGetUser.mock.callCount(), 1);

        const cookieStr = response.headers.get('set-cookie');
        assert.equal(cookieStr, undefined);

        const locationStr = response.headers.get('location');
        const callbackURL = new URL(locationStr);
        assert.ok(callbackURL.href.includes(options.clients[0].redirect_uris[0]));
    });

    test('no need for consent, using showConsent', async () => {
        const url = new URL('http://localhost:8080/api/oidc/authorize');
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('client_id', 'foo');
        url.searchParams.set('redirect_uri', 'http://localhost:3000/api/callback');
        const request = new Request(url, { method: 'get' });
        mockGetUser.mock.mockImplementationOnce(() =>
            Promise.resolve({
                sub: '123',
                email: 'test@example.com'
            })
        );
        options.showConsent = () => false;
        const response = await handleRoute(request, request, options);
        assert.equal(response.status, 302);
        assert.equal(mockGetUser.mock.callCount(), 1);

        const cookieStr = response.headers.get('set-cookie');
        assert.equal(cookieStr, undefined);

        const locationStr = response.headers.get('location');
        const callbackURL = new URL(locationStr);
        assert.ok(callbackURL.href.includes(options.clients[0].redirect_uris[0]));
        assert.ok(callbackURL.searchParams.has('code'));
    });

    test('works as HTTP POST', async () => {
        const url = new URL('http://localhost:8080/api/oidc/authorize');
        const request = new Request(url, {
            method: 'post',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                response_type: 'code',
                client_id: 'foo',
                redirect_uri: 'http://localhost:3000/api/callback'
            }).toString()
        });
        mockGetUser.mock.mockImplementationOnce(() =>
            Promise.resolve({
                sub: '123',
                email: 'test@example.com'
            })
        );
        options.showConsent = () => false;
        const response = await handleRoute(request, request, options);
        assert.equal(response.status, 302);
        assert.equal(mockGetUser.mock.callCount(), 1);

        const cookieStr = response.headers.get('set-cookie');
        assert.equal(cookieStr, undefined);

        const locationStr = response.headers.get('location');
        const callbackURL = new URL(locationStr);
        assert.ok(callbackURL.href.includes(options.clients[0].redirect_uris[0]));
        assert.ok(callbackURL.searchParams.has('code'));
    });
});
