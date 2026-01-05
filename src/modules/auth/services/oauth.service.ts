import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';

import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { SessionPayload, AuthorizationCodePayload } from '../interfaces';
import { LoginParamsDto, TokenRequestDto, AuthorizeParamsDto, LoginDto, GrantType } from '../dtos';
import { AuthException } from '../exceptions/auth.exception';
import { User } from 'src/modules/users/entities';

import { EnvironmentVariables } from 'src/config';
import { Application } from 'src/modules/access/entities';
import { AuthService } from './auth.service';
import { TokenService } from './token.service';

@Injectable()
export class OAuthService {
  constructor(
    @InjectRepository(Application) private appRepository: Repository<Application>,
    // @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private configService: ConfigService<EnvironmentVariables>,
    private tokenService: TokenService,
    private authService: AuthService,
  ) {}

  async resolveAuthorizeRedirectUrl(params: AuthorizeParamsDto, sessionId?: string) {
    const application = await this.validateApplication(params.clientId, params.redirectUri);

    const session = sessionId ? await this.getSession(sessionId) : null;

    if (!session) {
      return await this.redirectToLoginWithPendingRequest(params);
    }

    await this.authService.checkUserAppAccess(session.userId, application.id);

    return this.redirectWithAuthorizationCode(session, params);
  }

  async login(dto: LoginDto) {
    const user = await this.authService.authenticateUser(dto);
    return await this.createSession(user);
  }

  async processTokenRequest(dto: TokenRequestDto) {
    const app = await this.appRepository.findOne({ where: { clientId: dto.clientId, isActive: true } });
    if (!app) throw new UnauthorizedException('Invalid client id.');

    if (app.isConfidential) {
      if (!dto.clientSecret) throw new UnauthorizedException('Client secret is required.');
      const isSecretValid = await bcrypt.compare(dto.clientSecret, app.clientSecret);
      if (!isSecretValid) {
        throw new UnauthorizedException('Invalid client secret.');
      }
    }

    if (dto.grantType === GrantType.AUTHORIZATION_CODE) {
      return await this.exchangeAuthorizationCode(dto);
    }

    return await this.tokenService.rotateRefreshToken(dto.refreshToken, dto.clientId);
  }

  private async exchangeAuthorizationCode(params: TokenRequestDto) {
    const key = `auth_code:${params.code}`;
    const context = await this.cacheManager.get<AuthorizationCodePayload>(key);

    if (!context) {
      throw new UnauthorizedException('Invalid or expired authorization code');
    }

    if (context.clientId !== params.clientId || context.redirectUri !== params.redirectUri) {
      throw new UnauthorizedException('Invalid client');
    }

    await this.cacheManager.del(key);

    return await this.tokenService.generateTokenPair({
      sub: context.userId,
      clientId: context.clientId,
      scope: context.scope,
    });
  }

  async resolvePostLoginRedirect(params: LoginParamsDto) {
    const { authRequestId } = params;
    const loginUrl = this.configService.getOrThrow<string>('IDENTITY_HUB_APPS_PATH');
    if (authRequestId) {
      const pendingReq = await this.consumePendingOAuthRequest(authRequestId);

      if (!pendingReq) return loginUrl;

      const authorizeUrl = new URL('/oauth/authorize');
      authorizeUrl.searchParams.set('client_id', pendingReq.clientId);
      authorizeUrl.searchParams.set('redirect_uri', pendingReq.redirectUri);
      authorizeUrl.searchParams.set('response_type', 'code');
      if (pendingReq.scope) {
        authorizeUrl.searchParams.set('scope', pendingReq.scope);
      }

      if (pendingReq.state) {
        authorizeUrl.searchParams.set('state', pendingReq.state);
      }
      return authorizeUrl.toString();
    }

    return loginUrl;
  }

  resolveLoginErrorRedirect(error: AuthException, params: LoginParamsDto) {
    const { authRequestId } = params;
    const url = new URL(this.configService.getOrThrow<string>('IDENTITY_HUB_LOGIN_PATH'));
    url.searchParams.set('error', error.code);
    if (authRequestId) {
      url.searchParams.set('auth_request_id', authRequestId);
    }
    console.log(url);
    return url.toString();
  }

  private async createSession(user: User): Promise<string> {
    const sessionId = crypto.randomUUID();
    const key = `session:${sessionId}`;
    const LABORAL_HOURS_MS = 10 * 60 * 60 * 1000;
    const payload: SessionPayload = {
      userId: user.id,
      fullName: user.fullName,
    };
    await this.cacheManager.set(key, payload, LABORAL_HOURS_MS);
    return sessionId;
  }

  private async getSession(sessionId: string) {
    const key = `session:${sessionId}`;
    const session = await this.cacheManager.get<SessionPayload>(key);
    return session ?? null;
  }

  private async generateAuthorizationCode(context: AuthorizationCodePayload) {
    // code for exchange tokens
    const code = crypto.randomUUID();
    const key = `auth_code:${code}`;
    await this.cacheManager.set(key, context, 5 * 60 * 1000);
    return code;
  }

  private async createPendingOAuthRequest(data: AuthorizeParamsDto) {
    // save all query params for login redirect
    const oAuthRequestId = crypto.randomUUID();
    const key = `pending_oauth:${oAuthRequestId}`;
    await this.cacheManager.set(key, data, 5 * 60 * 1000);
    return oAuthRequestId;
  }

  private async consumePendingOAuthRequest(oAuthRequestId: string) {
    const key = `pending_oauth:${oAuthRequestId}`;
    const data = await this.cacheManager.get<AuthorizeParamsDto>(key);
    if (!data) return null;
    await this.cacheManager.del(key);
    return data;
  }

  private async validateApplication(clientId: string, redirectUri: string) {
    const application = await this.appRepository.findOne({
      where: { clientId, isActive: true },
    });

    if (!application) {
      throw new UnauthorizedException('Invalid client id.');
    }

    if (!application.redirectUris.includes(redirectUri)) {
      throw new UnauthorizedException('Invalid redirect uri.');
    }

    return application;
  }

  private async redirectToLoginWithPendingRequest(params: AuthorizeParamsDto) {
    const oAuthRequestId = await this.createPendingOAuthRequest(params);
    const loginUrl = new URL(this.configService.getOrThrow('IDENTITY_HUB_LOGIN_PATH'));
    loginUrl.searchParams.set('auth_request_id', oAuthRequestId);
    return loginUrl.toString();
  }

  private async redirectWithAuthorizationCode(session: SessionPayload, params: AuthorizeParamsDto) {
    const code = await this.generateAuthorizationCode({
      userId: session.userId,
      clientId: params.clientId,
      redirectUri: params.redirectUri,
    });
    const redirectUri = new URL(params.redirectUri);
    redirectUri.searchParams.set('code', code);
    return redirectUri.toString();
  }
}
