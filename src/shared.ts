import {
  ValidateClientFunction,
  Client,
  ClientValidationMeta,
  ErrorDTO,
  ERROR_CODE,
} from './types';
import { ERROR_CODES } from './errors';

export const validateClient: ValidateClientFunction = (
  client: Client,
  meta: Partial<ClientValidationMeta>
): ErrorDTO | void => {
  if (client == null) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'unregistered client',
    };
  }

  if (client.clientId !== meta.clientId) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'invalid client_id',
    };
  }

  // TODO check base path instead of equality
  if (meta.redirectUri && client.redirectUri !== meta.redirectUri) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'invalid redirection_uri',
    };
  }

  if (!meta.redirectUri && !client.redirectUri) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'missing redirection_uri',
    };
  }

  if (meta.clientSecret && client.clientSecret !== meta.clientSecret) {
    return {
      error: ERROR_CODES.unauthorized_client as ERROR_CODE,
      error_description: 'invalid client_secret',
    };
  }
};
