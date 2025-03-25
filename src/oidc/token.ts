import { SignJWT } from 'jose';
import type {
    TokenRequestGrant,
    GrantType,
    OAuthClient,
    TokenRequestMeta,
    Grant,
    AuthNZOptions,
    Claims, TokenResponse
} from '../types/index.ts';
import {
    CONTENT_TYPES,
    GRANT_TYPES,
    HTTP_LITERALS,
    ID_TOKEN,
    METADATA_LITERALS,
    OIDC_PARAMS,
    SCOPES,
    TOKEN_REQUEST_GRANTS
} from '../constants.ts';
import { getScopeSet, sanitizeBodyParams } from '../utils.ts';
import {
    getUrl,
    validateDuplicates,
    validateURIForFragment,
    validateURIForTLS,
    validateURIHttpMethodForPost
} from '../validation.ts';
import {
    AuthnzError,
    AuthorizationServerError,
    ERROR_DESCRIPTIONS,
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    toErrorDTO,
    UnsupportedGrantTypeError
} from '../errors.ts';
import { clientAuthentication, clientValidation } from './client.ts';
import { validateGrant } from './grant.ts';
import { generateAccessToken, generateIdToken } from './tokens.ts';

export const validateTokenRequest = async (
    requestDetails: {
        url: string;
        method: string;
        headers: Headers;
        body: FormData;
    },
    options: AuthNZOptions
): Promise<TokenRequestMeta> => {
    let body: Record<string, any>;

    const { url: uri, method, headers, body: formData } = requestDetails;
    const url = getUrl(uri);

    if (headers.get(HTTP_LITERALS.content_type) !== CONTENT_TYPES.form) {
        throw new InvalidRequestError(
            ERROR_DESCRIPTIONS.invalid_content_type,
            "The token request's content-type must be application/x-www-form-urlencoded"
        );
    }

    body = Object.fromEntries(formData.entries());

    // 1) grant_type is mandatory
    const grantType: GrantType = String(body[OIDC_PARAMS.grant_type]) as GrantType;
    if (grantType == null) {
        throw new InvalidRequestError(ERROR_DESCRIPTIONS.missing_mandatory_parameter, OIDC_PARAMS.grant_type);
    }

    // 2) finding out the grant type
    const grant: TokenRequestGrant = TOKEN_REQUEST_GRANTS[grantType];
    if (grant == null) {
        throw new UnsupportedGrantTypeError(
            ERROR_DESCRIPTIONS.unsupported_grant_type,
            `Supported grant types: ${Object.values(GRANT_TYPES).join()}`
        );
    }

    // 3) Checking mandatory params
    for (const mandatoryParam of grant.mandatoryParams) {
        if (body[mandatoryParam] == null) {
            throw new InvalidRequestError(ERROR_DESCRIPTIONS.missing_mandatory_parameter, mandatoryParam);
        }
    }

    // 4) Must use TLS as described in rfc6749 3.2
    // @see https://www.rfc-editor.org/rfc/rfc6749#section-3.2
    validateURIForTLS(url);

    // 5) The client MUST use the HTTP "POST" method when making access token requests. rfc6749 3.2
    // @see https://www.rfc-editor.org/rfc/rfc6749#section-3.2
    validateURIHttpMethodForPost(method);

    // The endpoint URI MUST NOT include a fragment component rfc6749 3.2
    // @see https://www.rfc-editor.org/rfc/rfc6749#section-3.2
    validateURIForFragment(url);

    // The authorization server MUST ignore unrecognized request parameters.
    const allowedParams = [...grant.mandatoryParams, ...grant.optionalParams];
    body = sanitizeBodyParams(body, allowedParams);

    // params MUST NOT be included more than once rfc6749 3.2
    // @see https://www.rfc-editor.org/rfc/rfc6749#section-3.2
    validateDuplicates(new URLSearchParams(body));

    const tokenRequestMeta = {
        grantType: grantType
    } as TokenRequestMeta;

    for (const allowedParam of allowedParams) {
        const param = body[allowedParam];
        if (param != null) {
            tokenRequestMeta[allowedParam] = param;
        }
    }

    if (body[OIDC_PARAMS.scope]) {
        tokenRequestMeta.scopeSet = new Set(body[OIDC_PARAMS.scope].split(' '));
    }

    return tokenRequestMeta;
};

export const handleTokenRequest = async <RequestType>(
    req: Request,
    originalRequest: RequestType,
    options: AuthNZOptions
): Promise<Response> => {
    let client: OAuthClient;
    try {
        const { url, method, headers } = req;
        const body = await req.formData();

        const { authenticatedClient } = await clientAuthentication(headers, body, options);
        const meta = await validateTokenRequest({ url, method, headers, body }, options);
        client = await clientValidation(authenticatedClient, meta, options);

        const grant: Grant = await options.database.fetch('grant', 'code', meta.code);
        await validateGrant(grant, client, meta);

        const { access_token, type } = await generateAccessToken(grant, client, meta, options);
        const payload = {
            access_token: access_token,
            token_type: type,
            expires_in: 7200
        } as TokenResponse;

        if (getScopeSet(grant.scope).has(SCOPES.openid)) {
            payload.id_token = await generateIdToken(grant, client, meta, options);
        }

        return Response.json(payload, {
            headers: new Headers({
                'Cache-Control': 'no-store',
                Pragma: 'no-cache'
            })
        });
    } catch (error) {
        const headers = new Headers({
            'Content-Type': 'application/json; charset=UTF-8',
            'Cache-Control': 'no-store',
            Pragma: 'no-cache'
        });

        const responseInit = {
            status: 400,
            statusText: 'Bad Request',
            headers
        } as ResponseInit;

        if (!(error instanceof AuthnzError)) {
            console.error(error);
            error = new AuthorizationServerError(
                error.message,
                'Some unhandled error occurred during the token request.'
            );
        }

        if (error instanceof InvalidClientError) {
            responseInit.status = 401;
            headers.append(
                'WWW-Authenticate',
                client?.token_endpoint_auth_method ?? METADATA_LITERALS.client_secret_basic
            );
        }

        return new Response(JSON.stringify(toErrorDTO(error)), responseInit);
    }
};
