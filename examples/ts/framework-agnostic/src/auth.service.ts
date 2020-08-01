import { Injectable } from '@nestjs/common';
import { Client } from 'auth-nz';

@Injectable()
export class AuthService {
  clients: Client[] = [
    {
      clientId: 'cb894e06',
      clientSecret: 'a28d04fdb176b2d1a6be95e8',
      redirectUri: 'https://oauth.pstmn.io/v1/callback',
    },
  ];

  async findClient(clientId: Client['clientId']): Promise<Client> {
    // Finding a client in a real world scenario is usually an async operation
    return this.clients.find((client) => client.clientId === clientId);
  }
}
