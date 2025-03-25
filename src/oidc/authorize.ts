import * as cookie from 'cookie';
import type {
    OAuthClient,
    AuthNZOptions,
    ResponseType,
    AuthorizationGrantType,
    AuthorizationRequestMeta,
    Grant, Claims, Scope
} from '../types/index.ts';
import {
    AUTHORIZATION_REQUEST_GRANTS,
    OIDC_PARAMS,
    CODE_CHALLENGE_METHOD_TYPES,
    HTTP_LITERALS,
    CONTENT_TYPES
} from '../constants.ts';
import {
    InvalidRequestError,
    ERROR_DESCRIPTIONS,
    AuthnzError,
    InvalidScopeError,
    handleError,
    toErrorDTO, AuthorizationServerError
} from '../errors.ts';
import {
    getUrl,
    validateClient,
    validateDuplicates,
    validateResponseType,
    validateURIForFragment,
    validateURIForTLS,
    validateParamValue,
    validateURIHttpMethodForGerOrPost,
    validateClientId,
    validateRedirectURI
} from '../validation.ts';
import { randomBytes } from 'node:crypto';
import { createAuthorizationGrant } from './grant.ts';
import { findClient } from './client.ts';

type ClientId = OAuthClient['client_id'];
type RedirectURI = string;
type State = string;

export const validateAuthorizeRequest = async (
    req: Request,
    options: AuthNZOptions
): Promise<AuthorizationRequestMeta> => {
    const uid = randomBytes(12).toString('hex');

    let params: URLSearchParams;
    let client: OAuthClient;
    let client_id: ClientId;
    let redirect_uri: RedirectURI;
    let state: State;
    let response_type: ResponseType;

    try {
        const url = getUrl(req.url);
        const contentType = req.headers.get(HTTP_LITERALS.content_type);

        /**
         * > Authorization Servers MUST support the use of the HTTP GET and POST methods
         */
        validateURIHttpMethodForGerOrPost(req.method);

        /**
         * > If using the HTTP GET method, the request parameters are serialized using URI Query String Serialization,
         * > per Section 13.1. If using the HTTP POST method, the request parameters are serialized using Form Serialization
         */
        if (req.method.toLowerCase() === HTTP_LITERALS.post && contentType === CONTENT_TYPES.form) {
            const bodyText = await req.text();
            params = new URLSearchParams(bodyText);
        } else if (req.method.toLowerCase() === HTTP_LITERALS.get) {
            params = url.searchParams;
        }

        response_type = params.get(OIDC_PARAMS.response_type) as ResponseType;
        client_id = params.get(OIDC_PARAMS.client_id);
        state = params.get(OIDC_PARAMS.state);
        redirect_uri = params.get(OIDC_PARAMS.redirect_uri);

        validateDuplicates(params);
        validateURIForFragment(url);
        validateURIForTLS(url);
        validateResponseType(response_type);
        validateClientId(client_id);
        validateRedirectURI(redirect_uri);

        const grant: AuthorizationGrantType = AUTHORIZATION_REQUEST_GRANTS[response_type];
        const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];

        for (const mandatoryParam of grant.mandatoryParams) {
            if (!params.has(mandatoryParam)) {
                throw new InvalidRequestError(ERROR_DESCRIPTIONS.missing_mandatory_parameter, mandatoryParam);
            }
        }

        client = await findClient(client_id, options);
        validateClient(client, { clientId: client_id, redirectUri: redirect_uri, grantType: grant.type });

        const authorizationRequestMeta = {
            uid,
            original_uri: url.href,
            client,
            steps: [
                {
                    type: 'login',
                    active: false,
                    completed: false
                },
                {
                    type: 'consent',
                    active: false,
                    completed: false
                }
            ]
        } as AuthorizationRequestMeta;

        /**
         * Populating request meta
         */
        for (const allowedParam of allowedParams) {
            const param = params.get(allowedParam);
            if (param != null) {
                authorizationRequestMeta[allowedParam] = param.trim();
            }
        }

        /**
         * Validating code_challenge_method value
         */
        if (authorizationRequestMeta.code_challenge_method) {
            validateParamValue<string>(
                authorizationRequestMeta.code_challenge_method.toLowerCase(),
                Object.keys(CODE_CHALLENGE_METHOD_TYPES),
                ERROR_DESCRIPTIONS.invalid_code_challenge_method
            );
        }

        /**
         * Scope handling & validation
         */
        if (authorizationRequestMeta.scope) {
            const scopes = authorizationRequestMeta.scope.split(' ') as Scope[];
            const requestedScopeSet = new Set<Scope>(scopes);
            const comparedScopes = (client.scope ?? options.defaultScope).split(' ') as Scope[];
            const toCompareSet = new Set<Scope>(comparedScopes);
            const isSubset = requestedScopeSet.isSubsetOf(toCompareSet);
            if (!isSubset) {
                const difference = requestedScopeSet.difference(toCompareSet);
                throw new InvalidScopeError(
                    ERROR_DESCRIPTIONS.invalid_scope,
                    `The invalid scope value(s): ${Array.from(difference.values()).join()}`
                )
            }
            authorizationRequestMeta.scopeSet = requestedScopeSet.intersection(toCompareSet);
        } else {
            const defaultScopes = (client.scope ?? options.defaultScope).split(' ') as Scope[];
            authorizationRequestMeta.scopeSet = new Set<Scope>(defaultScopes);
        }

        /**
         * Constructing claims requested
         */


        return authorizationRequestMeta;
    } catch (error) {
        if (!(error instanceof AuthnzError)) {
            error = new AuthorizationServerError(error.message, 'Some unhandled error was raised during the authorize request validation');
        }
        if (state) error.state = state;
        if (redirect_uri) error.redirect_uri = redirect_uri;
        throw error;
    }
};

export const redirectToSignIn = async (meta: AuthorizationRequestMeta, options: AuthNZOptions): Promise<Response> => {
    const stepUrl = new URL(`/api/oidc/step/${meta.uid}/login`, options.base);
    options.signInURL.searchParams.set('redirectTo', stepUrl.href);
    const setCookie = cookie.serialize('authnz:step:login', meta.uid, {
        path: stepUrl.pathname,
        domain: stepUrl.hostname,
        maxAge: 1200,
        secure: false,
        sameSite: 'lax'
    });
    const headers = new Headers();
    headers.append('Location', options.signInURL.href);
    headers.append('Set-Cookie', setCookie);
    return new Response(null, {
        status: 302,
        headers
    });
};

export const redirectToConsent = async (meta: AuthorizationRequestMeta, options: AuthNZOptions): Promise<Response> => {
    const stepUrl = new URL(`/api/oidc/step/${meta.uid}/decision`, options.base);
    options.consentURL.searchParams.set('redirectTo', stepUrl.href);
    const setCookie = cookie.serialize('authnz:step:consent', meta.uid, {
        path: stepUrl.pathname,
        domain: stepUrl.hostname,
        maxAge: 1200,
        secure: false,
        sameSite: 'lax'
    });
    const headers = new Headers();
    headers.append('Location', options.consentURL.href);
    headers.append('Set-Cookie', setCookie);
    return new Response(null, {
        status: 302,
        headers
    });
};

export const redirectToCallback = async (
    meta: AuthorizationRequestMeta,
    code: Grant['code'],
    options: AuthNZOptions
): Promise<Response> => {
    const redirectUrl = new URL(meta.redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (meta.state) {
        redirectUrl.searchParams.set('state', meta.state);
    }
    const headers = new Headers();
    headers.append('Location', redirectUrl.href);
    return new Response(null, {
        status: 302,
        headers
    });
};

export const handleAuthorizeRequest = async <RequestType>(
    request: Request,
    originalRequest: RequestType,
    options: AuthNZOptions
): Promise<Response> => {
    let meta: AuthorizationRequestMeta
    try {
        meta = await validateAuthorizeRequest(request, options);
        await options.database.insert('session', meta, meta.uid);

        const requestedScopes = meta.scopeSet;
        const claims: Claims = await options.getUser(originalRequest, requestedScopes);

        if (claims == null || claims.sub == null) {
            meta.steps.find((step) => step.type === 'login').active = true;
            return redirectToSignIn(meta, options);
        } else {
            await options.database.update('session', meta.uid, { claims });
        }

        if (options.showConsent(meta, claims)) {
            meta.steps.find((step) => step.type === 'consent').active = true;
            return redirectToConsent(meta, options);
        }

        const { code } = await createAuthorizationGrant(meta, claims, options);
        return redirectToCallback(meta, code, options);
    } catch (error) {
        if (!(error instanceof AuthnzError)) {
            console.error(error);
            error = new AuthorizationServerError(error.message, 'Some unhandled error was raised during the authorize request');
        }
        if (!error.state && meta && meta.state) error.state = meta.state;
        if (!error.redirect_uri && meta && meta.redirect_uri) error.redirect_uri = meta.redirect_uri;
        return handleError(toErrorDTO(error), options);
    }
};
