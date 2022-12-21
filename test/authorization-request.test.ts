import { parse } from 'querystring';
import {
    validateParamValue,
    validateQueryParams,
    validateURIForFragment,
    validateURIForTLS,
    validateURIHttpMethodForGerOrPost,
} from '../src/validation';
import { InvalidRequestError, ErrorCodes, ErrorDescriptions } from '../src/errors';
import { Request, Client, Settings } from '../src/types';
import { sanitizeQueryParams } from '../src/utils';
import { createAuthnzService } from '../src/authorization-server';

describe('validateURIForFragment', () => {
    it("throws if can't parse uri string to an URL", () => {
        expect(() => validateURIForFragment('this is not a valid uri')).toThrow(InvalidRequestError);
    });
    it('throws if uri string contains a hash fragment', () => {
        expect(() => validateURIForFragment('http://website.com/path#frag')).toThrow(InvalidRequestError);
    });
    it('succeeds', () => {
        expect(() => validateURIForFragment('http://website.com/path?lang=en')).not.toThrow();
    });
});

describe('validateURIForTLS', () => {
    it("throws if can't parse uri string to an URL", () => {
        expect(() => validateURIForTLS('this is not a valid uri')).toThrow(InvalidRequestError);
    });
    it("throws if uri's protocol is not https", () => {
        expect(() => validateURIForTLS('http://website.com/path')).toThrow(InvalidRequestError);
    });
    it('succeeds', () => {
        expect(() => validateURIForTLS('https://website.com/path?lang=en')).not.toThrow();
    });
});

describe('validateURIHttpMethod', () => {
    it('throws if method is not defined', () => {
        expect(validateURIHttpMethodForGerOrPost).toThrow(InvalidRequestError);
    });
    it('throws if method is not POST or GET', () => {
        ['PUT', 'PATCH', 'DELETE', 'OPTIONS', 'invalid'].forEach(method => {
            expect(() => validateURIHttpMethodForGerOrPost(method)).toThrow(InvalidRequestError);
        });
    });
    it('succeeds', () => {
        expect(() => validateURIHttpMethodForGerOrPost('POST')).not.toThrow();
        expect(() => validateURIHttpMethodForGerOrPost('GET')).not.toThrow();
    });
});

describe('sanitizeQueryParams', () => {
    const validParams = ['lang', 'scope'];
    it('works for query objects. express/koa like', () => {
        expect(sanitizeQueryParams({ scope: '', lang: 'en', invalid: 'zzz' }, validParams)).toEqual({
            lang: 'en',
        });
    });
    it('works for queryStrings', () => {
        expect(sanitizeQueryParams('?lang=en&scope&invalid=zzz', validParams)).toEqual({
            lang: 'en',
        });
        expect(sanitizeQueryParams('lang=en&scope=&invalid=zzz', validParams)).toEqual({
            lang: 'en',
        });
    });
});

describe('validateQueryParams', () => {
    const validParams = ['lang', 'scope'];
    it('throws if there are duplicated query parameters', () => {
        expect(() => validateQueryParams('?lang=en&lang=hu&scope&invalid', validParams)).toThrow(InvalidRequestError);
    });
    it('throws if there are express/koa queryParser like arrays', () => {
        expect(() => validateQueryParams({ lang: ['en', 'hu'] }, validParams)).toThrow(InvalidRequestError);
    });
    it('good case', () => {
        expect(() => validateQueryParams('lang=en&scope=', validParams)).not.toThrow();
    });
});

describe('validateParamValue', () => {
    it('throws on missing params', () => {
        expect(validateParamValue).toThrow(InvalidRequestError);
        expect(() => validateParamValue(undefined, ['valid'])).toThrow(InvalidRequestError);
        expect(() => validateParamValue('test', undefined)).toThrow(InvalidRequestError);
    });
    it('throws if value is not present in validValues', () => {
        expect(() => validateParamValue<string>('test', ['valid', 'value'])).toThrow(InvalidRequestError);
    });
});

describe('AuthNZService.validateAuthorizeRequest()', () => {
    const clients = [
        {
            clientId: 'b75b7c4a',
            clientSecret: '1af8635fdfa33ad196481daa',
            redirectUri: 'https://localhost:1337/cb',
            confidential: true,
        },
    ];

    const getClient = async clientId => clients.find(c => c.clientId === clientId);

    const authService = createAuthnzService({ getClient, devMode: false });

    /**
     * -------------
     * Client Errors
     * -------------
     */
    describe('client errors', () => {
        it('good case', async () => {
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query: {
                    response_type: 'code',
                    client_id: clients[0].clientId,
                    state: 'csrf',
                    redirect_uri: 'https://localhost:1337/cb',
                },
            } as Request;
            const expected = {
                client: clients[0],
                state: 'csrf',
                redirectUri: 'https://localhost:1337/cb',
                originalUri: 'https://localhost/oauth/authorize',
                responseType: 'code',
                clientId: clients[0].clientId,
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('good case - PKCE', async () => {
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query: {
                    response_type: 'code',
                    client_id: clients[0].clientId,
                    state: 'csrf',
                    redirect_uri: 'https://localhost:1337/cb',
                    code_challenge: '9bb773d5',
                    code_challenge_method: 'sha256',
                },
            } as Request;
            const expected = {
                client: clients[0],
                state: 'csrf',
                redirectUri: 'https://localhost:1337/cb',
                originalUri: 'https://localhost/oauth/authorize',
                responseType: 'code',
                clientId: clients[0].clientId,
                codeChallenge: '9bb773d5',
                codeChallengeMethod: 'sha256',
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        // against open redirector attacks
        it('validates multiple redirect_uri parameters', async () => {
            const query = parse(
                `response_type=code&redirect_uri=${clients[0].redirectUri}&redirect_uri=${encodeURIComponent(
                    'https://malicious.site'
                )}`
            );
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query,
            } as Request;
            const expected = {
                clientError: {
                    error: ErrorCodes.invalid_request,
                    error_description: ErrorDescriptions.duplicate_query_parameter,
                },
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('validates missing client_id', async () => {
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query: {
                    response_type: 'code',
                },
            } as Request;
            const expected = {
                clientError: {
                    error: ErrorCodes.invalid_request,
                    error_description: ErrorDescriptions.missing_client_id,
                },
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('validates non existing clients - when findClient fn throws', async () => {
            const willThrow = () => Promise.reject();
            const _authService = createAuthnzService({ getClient: willThrow });
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query: {
                    response_type: 'code',
                    client_id: 'invalid',
                },
            } as Request;
            const expected = {
                clientError: {
                    error: ErrorCodes.unauthorized_client,
                    error_description: ErrorDescriptions.invalid_client,
                },
            };
            await expect(_authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        /**
         * --------------------
         * Unregistered Clients
         * --------------------
         */
        describe('unauthorized clients', () => {
            it('non existing client = findClient returns null|undefined', async () => {
                const req = {
                    method: 'GET',
                    uri: 'https://localhost/oauth/authorize',
                    query: {
                        response_type: 'code',
                        client_id: 'invalid',
                        state: 'csrf',
                    },
                } as Request;
                const expected = {
                    clientError: {
                        error: ErrorCodes.unauthorized_client,
                        error_description: ErrorDescriptions.unregistered_client,
                        state: 'csrf',
                    },
                };
                await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
            });

            // It is possible that the consumer-provided findClient function finds and
            // returns a different client model, E.g there is a bug in the find logic
            // etc. We must validate the matching client_id after the fn returns a client
            it('invalid client_id', async () => {
                const badClientModel = {
                    clientId: 'flawed',
                    clientSecret: 'secret',
                    redirectUri: 'w/e',
                    confidential: false,
                };
                const flawedFindClient = _ => Promise.resolve(badClientModel);
                const _authService = createAuthnzService({ getClient: flawedFindClient });
                const req = {
                    method: 'GET',
                    uri: 'https://localhost/oauth/authorize',
                    query: {
                        response_type: 'code',
                        client_id: clients[0].clientId,
                        state: 'csrf',
                    },
                } as Request;
                const expected = {
                    clientError: {
                        error: ErrorCodes.unauthorized_client,
                        error_description: ErrorDescriptions.invalid_client_id,
                        state: 'csrf',
                    },
                };
                await expect(_authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
            });

            it('invalid redirect_uri', async () => {
                const req = {
                    method: 'GET',
                    uri: 'https://localhost/oauth/authorize',
                    query: {
                        response_type: 'code',
                        client_id: clients[0].clientId,
                        redirect_uri: 'invalid',
                        state: 'csrf',
                    },
                } as Request;
                const expected = {
                    clientError: {
                        error: ErrorCodes.unauthorized_client,
                        error_description: ErrorDescriptions.invalid_redirect_uri,
                        state: 'csrf',
                    },
                };
                await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
            });

            // Missing redirect_uri. It shouldn't but it can still happen that the client
            // model doesn't have a registered redirect_uri nor we got one in the req
            // In this case we wouldn't be able to redirect
            it('missing redirect_uri', async () => {
                const req = {
                    method: 'GET',
                    uri: 'https://localhost/oauth/authorize',
                    query: {
                        response_type: 'code',
                        client_id: clients[0].clientId,
                        state: 'csrf',
                    },
                } as Request;
                const expected = {
                    clientError: {
                        error: ErrorCodes.unauthorized_client,
                        error_description: ErrorDescriptions.missing_redirect_uri,
                        state: 'csrf',
                    },
                };
                const _authService = createAuthnzService({
                    getClient: () =>
                        Promise.resolve({
                            clientId: clients[0].clientId,
                            clientSecret: clients[0].clientSecret,
                        } as Client),
                });
                await expect(_authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
            });
        });
    });

    /**
     * -------------
     *    Errors
     * -------------
     */
    describe('errors', () => {
        it('validates the URI for fragment component', async () => {
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize#frag',
                query: {
                    response_type: 'code',
                    client_id: clients[0].clientId,
                },
            } as Request;
            const expected = {
                error: {
                    error: ErrorCodes.invalid_request,
                    error_description: ErrorDescriptions.url_fragment,
                },
                redirectTo:
                    'https://localhost:1337/cb?error=invalid_request&error_description=the+request+must+not+contain+a+url+fragment',
                redirectUri: clients[0].redirectUri,
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('validates the URI for TLS', async () => {
            const req = {
                method: 'GET',
                uri: 'http://localhost/oauth/authorize',
                query: {
                    response_type: 'code',
                    client_id: clients[0].clientId,
                    redirectUri: clients[0].redirectUri,
                },
            } as Request;
            const expected = {
                error: {
                    error: ErrorCodes.invalid_request,
                    error_description: ErrorDescriptions.missing_tls,
                },
                redirectTo: 'https://localhost:1337/cb?error=invalid_request&error_description=must+use+TLS',
                redirectUri: clients[0].redirectUri,
            };
            const _authService = createAuthnzService({ getClient, devMode: false });
            await expect(_authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('validates the HTTP method', async () => {
            const req = {
                method: 'PUT',
                uri: 'https://localhost/oauth/authorize',
                query: {
                    response_type: 'code',
                    client_id: clients[0].clientId,
                    redirectUri: clients[0].redirectUri,
                },
            } as Request;
            const expected = {
                error: {
                    error: ErrorCodes.invalid_request,
                    error_description: ErrorDescriptions.invalid_http_method,
                },
                redirectTo:
                    'https://localhost:1337/cb?error=invalid_request&error_description=for+the+authorization+request+only+http+get+and+post+methods+are+supported',
                redirectUri: clients[0].redirectUri,
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('validates missing response_type param', async () => {
            const req = {
                method: 'POST', // post is allowed too
                uri: 'https://localhost/oauth/authorize',
                query: {
                    client_id: clients[0].clientId,
                    redirectUri: clients[0].redirectUri,
                },
            } as Request;
            const expected = {
                error: {
                    error: ErrorCodes.invalid_request,
                    error_description: ErrorDescriptions.missing_response_type,
                },
                redirectTo:
                    'https://localhost:1337/cb?error=invalid_request&error_description=the+%22response_type%22+parameter+is+mandatory',
                redirectUri: clients[0].redirectUri,
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('unsupported response_type', async () => {
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query: {
                    response_type: 'token',
                    client_id: clients[0].clientId,
                    redirectUri: clients[0].redirectUri,
                },
            } as Request;
            const expected = {
                error: {
                    error: ErrorCodes.unsupported_response_type,
                    error_description: ErrorDescriptions.unsupported_response_type,
                },
                redirectTo:
                    'https://localhost:1337/cb?error=unsupported_response_type&error_description=unsupported+response_type',
                redirectUri: clients[0].redirectUri,
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('validates duplicated parameter values', async () => {
            // To overcome the following errors we do a trick:
            // - An object literal cannot have multiple properties with the same name in strict mode.ts(1117)
            // - Duplicate identifier 'client_id'.ts(2300)
            const query = parse(`response_type=code&client_id=some&client_id=${clients[0].clientId}`);
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query,
            } as Request;
            const expected = {
                error: {
                    error: ErrorCodes.invalid_request,
                    error_description: ErrorDescriptions.duplicate_query_parameter,
                },
                redirectTo:
                    'https://localhost:1337/cb?error=invalid_request&error_description=duplicated+query+parameter',
                redirectUri: clients[0].redirectUri,
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('sanitizes excess unsupported parameters', async () => {
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query: {
                    response_type: 'code',
                    client_id: clients[0].clientId,
                    state: 'csrf',
                    runthis: 'some-bad-code',
                    clientid: 'fake',
                },
            } as Request;
            const expected = {
                client: clients[0],
                state: 'csrf',
                redirectUri: clients[0].redirectUri,
                originalUri: 'https://localhost/oauth/authorize',
                responseType: 'code',
                clientId: clients[0].clientId,
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('validates code_challenge_method type', async () => {
            const req = {
                method: 'GET',
                uri: 'https://localhost/oauth/authorize',
                query: {
                    response_type: 'code',
                    client_id: clients[0].clientId,
                    state: 'csrf',
                    code_challenge: '9bb773d5',
                    code_challenge_method: 'sha512',
                },
            } as Request;
            const expected = {
                error: {
                    error: ErrorCodes.invalid_request,
                    error_description: ErrorDescriptions.invalid_code_challenge_method,
                    state: 'csrf',
                },
                redirectTo:
                    'https://localhost:1337/cb?error=invalid_request&error_description=pkce+code_challenge_method+transform+algorithm+not+supported',
                redirectUri: clients[0].redirectUri,
            };
            await expect(authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });

        it('tests custom utilities', async () => {
            const req = {
                method: 'GET',
                origin: 'https://localhost',
                nextUrl: '/oauth/authorize',
                searchParams:
                    'response_type=code&client_id=b75b7c4a&state=csrf&code_challenge=9bb773d5&code_challenge_method=sha256',
            };
            const expected = {
                client: clients[0],
                codeChallenge: '9bb773d5',
                codeChallengeMethod: 'sha256',
                state: 'csrf',
                redirectUri: clients[0].redirectUri,
                originalUri: 'https://localhost/oauth/authorize',
                responseType: 'code',
                clientId: clients[0].clientId,
            };

            function CustomStrategy(settings: Settings) {
                settings.getQuery = (req: { searchParams: string }) => {
                    const urlParams = new URLSearchParams(req.searchParams);
                    const params = Object.fromEntries((urlParams as any).entries());
                    return params;
                };

                settings.getUri = (req: any) => `${req.origin}${req.nextUrl}`;
            }

            const _authService = createAuthnzService({ getClient });
            _authService.use(CustomStrategy);

            await expect(_authService.validateAuthorizeRequest(req)).resolves.toEqual(expected);
        });
    });
});
