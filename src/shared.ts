import {
  ValidateClientFunction,
  Client,
  ClientValidationMeta,
  ErrorDTO,
  ERROR_CODE,
} from './types';
import { ERROR_CODES, ERROR_DESCRIPTIONS } from './errors';

export const validateClient: ValidateClientFunction = (
  client: Client,
  meta: Partial<ClientValidationMeta>
): ErrorDTO | void => {
  if (client == null) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: ERROR_DESCRIPTIONS.unregistered_client,
    };
  }

  if (client.clientId !== meta.clientId) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: ERROR_DESCRIPTIONS.invalid_client_id,
    };
  }

  // TODO check base path instead of equality
  if (meta.redirectUri && client.redirectUri !== meta.redirectUri) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: ERROR_DESCRIPTIONS.invalid_redirect_uri,
    };
  }

  if (!meta.redirectUri && !client.redirectUri) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: ERROR_DESCRIPTIONS.missing_redirect_uri,
    };
  }

  if (meta.clientSecret && client.clientSecret !== meta.clientSecret) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: ERROR_DESCRIPTIONS.invalid_client_secret,
    };
  }
};
