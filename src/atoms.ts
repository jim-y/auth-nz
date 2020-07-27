import { ValidateClientFunction, Client, ClientValidationMeta } from './types';

export const validateClient: ValidateClientFunction = (
  client: Client,
  meta: Partial<ClientValidationMeta>
): void => {
  if (client == null) throw new Error('Unregistered client');
  if (client.clientId !== meta.clientId)
    throw new Error('Client authentication failed. Invalid Client ID!');
  // TODO check base path instead of equality
  if (meta.redirectUri && client.redirectUri !== meta.redirectUri)
    throw new Error(
      'Client authentication failed. Invalid Client redirection_uri!'
    );

  if (meta.clientSecret && client.clientSecret !== meta.clientSecret) {
    throw new Error('Client authentication failed. Invalid Client secret!');
  }
};
