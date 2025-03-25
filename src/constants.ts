export const OIDC_PARAMS = {
    // oauth
    response_type: 'response_type',
    grant_type: 'grant_type',
    client_id: 'client_id',
    client_secret: 'client_secret',
    redirect_uri: 'redirect_uri',
    code: 'code',
    scope: 'scope',
    state: 'state',
    // oidc
    nonce: 'nonce',
    prompt: 'prompt',
    max_age: 'max_age',
    id_token_hint: 'id_token_hint',
    ui_locales: 'ui_locales',
    login_hint: 'login_hint',
    acr_values: 'acr_values',
    claims: 'claims',
    request: 'request',
    request_uri: 'request_uri',
    // extensions
    // pkce
    code_verifier: 'code_verifier',
    code_challenge: 'code_challenge',
    code_challenge_method: 'code_challenge_method',
    // resource
    resource: 'resource'
} as const;

export const SCOPES = {
    openid: 'openid',
    email: 'email',
    profile: 'profile',
    address: 'address',
    phone: 'phone',
    offline_access: 'offline_access'
} as const;

export const CLAIMS = {
    sub: 'sub',
    name: 'name',
    given_name: 'given_name',
    family_name: 'family_name',
    middle_name: 'middle_name',
    nickname: 'nickname',
    preferred_username: 'preferred_username',
    profile: 'profile',
    picture: 'picture',
    website: 'website',
    email: 'email',
    email_verified: 'email_verified',
    gender: 'gender',
    birthdate: 'birthdate',
    zoneinfo: 'zoneinfo',
    locale: 'locale',
    phone_number: 'phone_number',
    phone_number_verified: 'phone_number_verified',
    address: 'address',
    updated_at: 'updated_at'
} as const;

export const SCOPE_CLAIMS = [SCOPES.profile, SCOPES.email, SCOPES.address, SCOPES.phone];

export const SCOPE_CLAIMS_MAP = {
    [SCOPES.profile]: [CLAIMS.name, CLAIMS.family_name, CLAIMS.given_name, CLAIMS.middle_name, CLAIMS.nickname, CLAIMS.preferred_username, CLAIMS.profile, CLAIMS.picture, CLAIMS.website, CLAIMS.gender, CLAIMS.birthdate, CLAIMS.zoneinfo, CLAIMS.locale, CLAIMS.updated_at],
    [SCOPES.email]: [CLAIMS.email, CLAIMS.email_verified],
    [SCOPES.address]: [CLAIMS.address],
    [SCOPES.phone]: [CLAIMS.phone_number, CLAIMS.phone_number_verified]
}

export const ID_TOKEN = 'id_token';
export const USERINFO = 'userinfo';

export const METADATA_LITERALS = {
    none: 'none',
    client_secret_post: 'client_secret_post',
    client_secret_basic: 'client_secret_basic',
    public: 'public',
    confidential: 'confidential'
} as const;

export const HTTP_LITERALS = {
    content_type: 'content-type',
    get: 'get',
    post: 'post'
} as const;

export const CONTENT_TYPES = {
    json: 'application/json',
    form: 'application/x-www-form-urlencoded'
} as const;

export const NOT_SUPPORTED_OIDC_PARAMS = {
    display: 'display',
    claims_locales: 'claims_locales'
};

export const RESPONSE_TYPES = {
    code: 'code'
} as const;

export const GRANT_TYPES = {
    authorization_code: 'authorization_code',
    refresh_token: 'refresh_token',
    client_credentials: 'client_credentials'
} as const;

export const PROMPT_TYPES = {
    none: 'none',
    login: 'login',
    consent: 'consent',
    select_account: 'select_account'
} as const;

export const TOKEN_REQUEST_GRANTS = {
    [GRANT_TYPES.authorization_code]: {
        type: GRANT_TYPES.authorization_code,
        mandatoryParams: [OIDC_PARAMS.grant_type, OIDC_PARAMS.code, OIDC_PARAMS.redirect_uri],
        optionalParams: [OIDC_PARAMS.client_id, OIDC_PARAMS.client_secret, OIDC_PARAMS.code_verifier, OIDC_PARAMS.scope]
    },
    [GRANT_TYPES.client_credentials]: {
        type: GRANT_TYPES.client_credentials,
        mandatoryParams: [OIDC_PARAMS.grant_type],
        optionalParams: [OIDC_PARAMS.scope]
    }
} as const;

export const CODE_CHALLENGE_METHOD_TYPES = {
    s256: 's256',
    sha256: 'sha256',
    plain: 'plain'
} as const;

export const AUTHORIZATION_GRANT_DECISIONS = {
    decline: 'decline',
    grant: 'grant'
} as const;

export const AUTHORIZATION_REQUEST_GRANTS = {
    [RESPONSE_TYPES.code]: {
        type: GRANT_TYPES.authorization_code,
        responseType: RESPONSE_TYPES.code,
        mandatoryParams: [OIDC_PARAMS.response_type, OIDC_PARAMS.client_id, OIDC_PARAMS.redirect_uri],
        optionalParams: [
            OIDC_PARAMS.scope,
            OIDC_PARAMS.state,
            OIDC_PARAMS.nonce,
            OIDC_PARAMS.code_challenge,
            OIDC_PARAMS.code_challenge_method,
            OIDC_PARAMS.claims,
            OIDC_PARAMS.prompt,
            OIDC_PARAMS.resource,
            OIDC_PARAMS.request,
            OIDC_PARAMS.request_uri
        ]
    }
} as const;
