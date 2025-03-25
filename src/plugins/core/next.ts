import { handleRoute } from '../../oidc/route.ts';
import type { AuthNZOptions, AuthNZPluginFactory, PluginOptions } from '../../types/index.ts';

export const nextPlugin: AuthNZPluginFactory = (pluginOptions?: PluginOptions) => ({
    type: 'core',
    handler: (options: AuthNZOptions) => ({
        GET: async (request: Request) => handleRoute(request, request, options),
        POST: async (request: Request) => handleRoute(request, request, options)
    })
});
