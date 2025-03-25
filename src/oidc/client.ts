import type { AuthNZOptions, OAuthClient, Scope, TokenRequestMeta } from '../types/index.ts';
import { METADATA_LITERALS, OIDC_PARAMS } from '../constants.ts';
import {
    ERROR_DESCRIPTIONS,
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    UnauthorizedClientError
} from '../errors.ts';

export const findClient = async (
    client_id: OAuthClient['client_id'],
    options: AuthNZOptions
): Promise<OAuthClient | null> => {
    if (options.clients) {
        const client = options.clients.find((client) => client.client_id === client_id);
        if (client) return client;
    }

    if (options.getClient) {
        return options.getClient(client_id);
    }

    return null;
};

export type ClientAuthenticationMethods =
    | typeof METADATA_LITERALS.client_secret_basic
    | typeof METADATA_LITERALS.client_secret_post;

export type ClientAuthenticationResponse = {
    authType?: ClientAuthenticationMethods;
    authenticatedClient?: OAuthClient;
};

/**
 * Client Authentication
 * The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described
 * in Section 9 of OpenID Connect Core 1.0 [OpenID.Core]. Other authentication methods MAY be defined by extensions.
 * If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in
 * Section 2.3.1 of OAuth 2.0 [RFC6749].
 */
export const clientAuthentication = async (
    headers: Headers,
    body: FormData,
    options: AuthNZOptions
): Promise<ClientAuthenticationResponse> => {
    let client: OAuthClient;
    let client_secret: string;
    let authType: ClientAuthenticationMethods;

    if (headers.has('authorization') && headers.get('authorization').startsWith('Basic')) {
        const base64ClientCredentials = headers.get('authorization').split(' ')[1];
        const credentials = Buffer.from(base64ClientCredentials, 'base64').toString('utf-8');
        const [clientId, clientSecret] = credentials.split(':');
        authType = METADATA_LITERALS.client_secret_basic;
        client = await findClient(clientId, options);
        client_secret = clientSecret;
    }

    if (body.has(OIDC_PARAMS.client_id) && body.has(OIDC_PARAMS.client_secret)) {
        if (authType != null) {
            throw new InvalidRequestError(
                ERROR_DESCRIPTIONS.multiple_client_authentication_mechanism,
                'The client tried to authenticate with multiple mechanisms'
            );
        }
        authType = METADATA_LITERALS.client_secret_post;
        client = await findClient(String(body.get(OIDC_PARAMS.client_id)), options);
        client_secret = String(body.get(OIDC_PARAMS.client_secret));
    }

    if (client && client_secret) {
        if (client.client_type === METADATA_LITERALS.public) {
            throw new InvalidRequestError(
                ERROR_DESCRIPTIONS.public_client_must_not_authenticate,
                'Public clients must not attempt to do client authentication with the authorization server'
            );
        } else if (client.client_type === METADATA_LITERALS.confidential && client.client_secret !== client_secret) {
            throw new InvalidClientError(
                ERROR_DESCRIPTIONS.invalid_client_authentication,
                'Failed client authentication'
            );
        }
    } else if (client && !client_secret) {
        throw new InvalidClientError(
            ERROR_DESCRIPTIONS.missing_client_authentication_parameters,
            'Mandatory parameters missing for client authentication'
        );
    }

    return {
        authType,
        authenticatedClient: client
    };
};

/**
 * Client validation
 */
export const clientValidation = async (
    authenticatedClient: OAuthClient,
    meta: TokenRequestMeta,
    options: AuthNZOptions
): Promise<OAuthClient> => {
    let client: OAuthClient;

    if (authenticatedClient == null && meta.client_id == null) {
        throw new InvalidClientError(
            ERROR_DESCRIPTIONS.missing_client_authentication_parameters,
            'authentication is needed or client_id is required for public clients'
        );
    }

    if (authenticatedClient && meta.client_id && authenticatedClient.client_id !== meta.client_id) {
        throw new InvalidClientError(
            ERROR_DESCRIPTIONS.invalid_client_authentication,
            'Mismatching client_id between client_id included in request params and client authentication'
        );
    }

    if (authenticatedClient == null && meta.client_id) {
        client = await findClient(meta.client_id, options);

        if (client == null) {
            throw new InvalidClientError(ERROR_DESCRIPTIONS.invalid_client_authentication, 'Invalid client');
        }

        if (client && client.client_type === METADATA_LITERALS.confidential) {
            throw new InvalidClientError(
                ERROR_DESCRIPTIONS.confidential_clients_must_authenticate,
                'confidential clients must authenticate'
            );
        }
    }

    if (client == null && authenticatedClient) {
        client = authenticatedClient;
    }

    if (!client.grant_types.includes(meta.grantType)) {
        throw new UnauthorizedClientError(
            ERROR_DESCRIPTIONS.unsupported_grant_type_for_client,
            'Invalid grant type for this client'
        );
    }

    /**
     * Scope handling & validation once we know the possible set of valid scopes
     */
    if (meta.scope) {
        const scopes = meta.scope.split(' ') as Scope[];
        const requestedScopeSet = new Set<Scope>(scopes);
        const comparedScopes = (client.scope ?? options.defaultScope).split(' ') as Scope[];
        const toCompareSet = new Set<Scope>(comparedScopes);
        const isSubset = requestedScopeSet.isSubsetOf(toCompareSet);
        if (!isSubset) {
            const difference = requestedScopeSet.difference(toCompareSet);
            throw new InvalidScopeError(
                ERROR_DESCRIPTIONS.scope_error,
                `the invalid scope value(s): ${Array.from(difference.values()).join()}`
            );
        }
        meta.scopeSet = requestedScopeSet.intersection(toCompareSet);
    }

    return client;
};
