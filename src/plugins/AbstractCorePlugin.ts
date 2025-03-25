import type { AuthNZOptions, PluginOptions } from '../types/index.ts';

export abstract class AbstractCorePlugin<RequestType = unknown> {
    type = 'core';
    pluginOptions: PluginOptions;

    #options: AuthNZOptions;

    constructor(pluginOptions?: PluginOptions) {
        this.pluginOptions = pluginOptions;
    }

    set options(options: AuthNZOptions) {
        this.#options = options;
    }

    get options(): AuthNZOptions {
        return this.#options;
    }

    abstract convertRequest(request: RequestType): Request;
    abstract getHandler(): unknown;
}