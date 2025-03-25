import type { AuthNZOptions } from '../types/index.ts';
import { resolveConsentStep, resolveLoginStep } from './steps.ts';
import { handleTokenRequest } from './token.ts';
import { handleAuthorizeRequest } from './authorize.ts';
import { getMetadata } from './metadata.ts';

export const handleRoute = async <RequestType>(request: Request, originalRequest: RequestType, options: AuthNZOptions): Promise<Response> => {
    const url = new URL(request.url);
    const paths = url.pathname.split('/').toReversed();
    const route = paths[0];

    if (url.href.includes('/.well-known/openid-configuration')) {
        return Response.json(getMetadata(request, options));
    }

    switch (route) {
        case 'authorize': {
            return handleAuthorizeRequest<RequestType>(request, originalRequest, options);
        }
        case 'login': {
            return resolveLoginStep<RequestType>(request, originalRequest, options);
        }
        case 'token': {
            return handleTokenRequest(request, originalRequest, options);
        }
        case 'decision': {
            return resolveConsentStep<RequestType>(request, originalRequest, options)
        }
        default: {
            return new Response(null, {
                status: 404,
                statusText: `Route (${route}) not found!`
            });
        }
    }
}