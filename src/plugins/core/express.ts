import type { Request as ExpressRequest, Response as ExpressResponse } from 'express';
import { handleRoute } from '../../oidc/route.ts';
import type { AuthNZOptions, AuthNZPluginFactory, PluginOptions } from '../../types/index.ts';

const convertRequest = (request: ExpressRequest): Request => {
    const protocol = request.protocol;
    const host = request.get('host');
    const url = new URL(request.originalUrl, `${protocol}://${host}`);
    const headers = new Headers();
    Object.entries(request.headers).forEach(([key, value]) => {
        headers.append(key, String(value));
    });

    const requestInit = {
        method: request.method,
        headers: headers,
        body: undefined
    };

    if (['POST', 'PUT', 'PATCH'].includes(request.method) && request.body) {
        const contentType = request.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            requestInit.body = JSON.stringify(request.body);
        } else if (contentType && contentType.includes('application/x-www-form-urlencoded')) {
            const params = new URLSearchParams();
            Object.entries(request.body).forEach(([key, value]) => {
                params.append(key, String(value));
            });
            requestInit.body = params.toString();
        } else {
            requestInit.body = request.body;
        }
    }
    return new Request(url.href, requestInit);
};

const handleResponse = async (response: Response, expressResponse: ExpressResponse): Promise<void> => {
    if (response.status) expressResponse.status(response.status);
    for (const [key, value] of response.headers.entries()) {
        expressResponse.set(key, value);
    }
    if (response.status === 302) {
        expressResponse.redirect(expressResponse.get('Location'));
    } else {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const jsonData = await response.json();
            expressResponse.json(jsonData);
        } else {
            const bodyText = await response.text();
            expressResponse.send(bodyText);
        }
    }
};

export const expressPlugin: AuthNZPluginFactory = (pluginOptions: PluginOptions) => ({
    type: 'core',
    handler: (options: AuthNZOptions) => async (originalRequest: ExpressRequest, originalResponse: ExpressResponse) => {
        const response: Response = await handleRoute<ExpressRequest>(
            convertRequest(originalRequest),
            originalRequest,
            options
        );
        await handleResponse(response, originalResponse);
    }
});
