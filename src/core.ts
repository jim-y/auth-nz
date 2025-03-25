import { expressPlugin } from './plugins/index.ts';
import { InMemoryAdapter } from './database/in-memory.ts';
import type {
    AuthNZOptions,
    AuthNZService,
    AuthorizationRequestMeta,
} from './types/index.ts';
import { CustomEvents } from './database/custom-events.ts';
import { SCOPES } from './constants.ts';
import { inspect } from 'node:util';
import { randomBytes } from 'node:crypto';

export const createService = (options: AuthNZOptions): AuthNZService => {
    const baseOptions: AuthNZOptions = Object.assign(
        {
            mountPath: '/api/oidc',
            database: new InMemoryAdapter() as AuthNZOptions['database'],
            signingKey: randomBytes(32).toString('hex'),
            signInURL: new URL('/auth/sign-in', options.base),
            consentURL: new URL('/auth/oidc/consent', options.base),
            errorURL: new URL('/auth/oidc/error', options.base),
            showConsent(meta: AuthorizationRequestMeta) {
                if (meta.client.trusted) return false;
                if (meta.scopeSet.size === 0 || (meta.scopeSet.size === 1 && meta.scopeSet.has(SCOPES.openid))) {
                    return false;
                }
                return true;
            },
            defaultScope: [SCOPES.openid, SCOPES.email].join(' '),
            authorizationCodeTTL: 120000,
            logLevel: 2
        },
        options
    );

    // todo if options.clients == null then options.getClient must not be null
    // todo options.clients shouldn't have duplicated client_ids
    // todo validation

    const plugins = baseOptions.plugins ?? [expressPlugin()];
    const corePlugins = plugins.filter((plugin) => plugin.type === 'core');

    if (!corePlugins.length) {
        corePlugins.push(expressPlugin());
    }

    if (corePlugins.length > 1) {
        throw new Error('Only one core plugin (type = core) can be used.');
    }

    const corePlugin = corePlugins[0];

    const service: AuthNZService = {
        handler: corePlugin.handler(baseOptions),
        options: baseOptions
    } as AuthNZService;

    if (options.logLevel >= 2) {
        baseOptions.database.on(CustomEvents.insert, (details) => {
            console.log('Database insert:', inspect(details, { depth: null, colors: true }));
        });

        baseOptions.database.on(CustomEvents.fetch, (details) => {
            console.log('Database fetch:', inspect(details, { depth: null, colors: true }));
        });

        baseOptions.database.on(CustomEvents.update, (details) => {
            console.log('Database update:', inspect(details, { depth: null, colors: true }));
        });
    }

    return service;
};
