import { Controller, Get, Req, Render } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request } from 'express';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('oauth/authorize')
  @Render('dialog')
  async getAuthorization(@Req() req: Request): Promise<any> {
    return { ...(req as any).authorizationServer };
  }
}
