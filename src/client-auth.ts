import basicAuth from 'basic-auth';

import { Client } from './types';

export interface BasicAuth {
  clientId: Client['clientId'];
  clientSecret: Client['clientSecret'];
}

export const authenticateClient = (req): BasicAuth => {
  const user = basicAuth(req);
  if (user == null) return null;
  return {
    clientId: user.name,
    clientSecret: user.pass,
  };
};
