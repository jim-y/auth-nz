import * as cookie from 'cookie';
import type { AuthorizationRequestMeta, AuthNZOptions, Claims } from '../types/index.ts';
import { createAuthorizationGrant } from './grant.ts';
import { redirectToConsent, redirectToCallback } from './authorize.ts';
import { AUTHORIZATION_GRANT_DECISIONS } from '../constants.ts';
import {
    AccessDeniedError,
    AuthnzError,
    AuthorizationServerError,
    ERROR_DESCRIPTIONS,
    handleError,
    toErrorDTO
} from '../errors.ts';

export const resolveLoginStep = async <RequestType>(
    request: Request,
    originalRequest: RequestType,
    options: AuthNZOptions
): Promise<Response> => {
    let meta: AuthorizationRequestMeta;
    try {
        const cookies = cookie.parse(request.headers.get('Cookie') || '');
        const cookieForStep = cookies['authnz:step:login'];
        meta = await options.database.fetch<AuthorizationRequestMeta>('session', cookieForStep);
        const claims: Claims = await options.getUser(originalRequest, meta.scopeSet);

        if (!claims?.sub) {
            return new Response(null, {
                status: 401,
                statusText: 'Unauthorized'
            });
        }

        const step = meta.steps.find((step) => step.type === 'login');
        step.active = false;
        step.completed = true;
        meta.claims = claims;

        if (options.showConsent(meta, claims)) {
            meta.steps.find((step) => step.type === 'consent').active = true;
            return redirectToConsent(meta, options);
        } else {
            const { code } = await createAuthorizationGrant(meta, meta.claims, options);
            return redirectToCallback(meta, code, options);
        }
    } catch (error) {
        if (!(error instanceof AuthnzError)) {
            error = new AuthorizationServerError(
                error.message,
                'Some unhandled error was raised during the resolve login step.'
            );
        }
        if (!error.redirect_uri && meta && meta.redirect_uri) error.redirect_uri = meta.redirect_uri;
        return handleError(toErrorDTO(error), options);
    }
};

export const resolveConsentStep = async <RequestType>(
    request: Request,
    originalRequest: RequestType,
    options: AuthNZOptions
): Promise<Response> => {
    let redirect_uri: string;
    try {
        const cookies = cookie.parse(request.headers.get('Cookie') || '');
        const cookieForStep = cookies['authnz:step:consent'];
        const meta = await options.database.fetch<AuthorizationRequestMeta>('session', cookieForStep);
        const step = meta.steps.find((step) => step.type === 'consent');

        redirect_uri = meta.redirect_uri;

        let body: Record<string, any>;
        if (request.headers.get('content-type') === 'application/json') {
            body = await request.json();
        } else if (request.headers.get('content-type') === 'application/x-www-form-urlencoded') {
            const formData = await request.formData();
            body = Object.fromEntries(formData.entries());
        }

        const decision = body['decision'];

        if (decision !== AUTHORIZATION_GRANT_DECISIONS.grant && decision !== '1' && decision !== 1) {
            throw new AccessDeniedError(
                ERROR_DESCRIPTIONS.denied_authorization_request,
                'the resource owner denied the grant'
            );
        }

        step.active = false;
        step.completed = true;

        const { code } = await createAuthorizationGrant(meta, meta.claims, options);
        return redirectToCallback(meta, code, options);
    } catch (error) {
        if (!(error instanceof AuthnzError)) {
            error = new AuthorizationServerError(
                error.message,
                'Some unhandled error was raised during the resolve consent step.'
            );
        }
        if (!error.redirect_uri && redirect_uri) error.redirect_uri = redirect_uri;
        return handleError(toErrorDTO(error), options);
    }
};
