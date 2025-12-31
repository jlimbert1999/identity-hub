import {
  Inject,
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';

import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import {
  AuthDto,
  LoginParamsDto,
  RefreshTokenDto,
  TokenRequestDto,
  AuthorizeParamsDto,
} from '../dtos';
import {
  PendingAuthRequest,
  RefreshTokenPayload,
  AuthorizationContext,
  GenerateTokenProperties,
} from '../interfaces';
import { AuthErrorCode, AuthException } from '../exceptions/auth.exception';
import { User } from 'src/modules/users/entities';

@Injectable()
export class SSOAuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private jwtService: JwtService,
  ) {}

  async login({ login, password }: AuthDto): Promise<User> {
    const userDB = await this.userRepository
      .createQueryBuilder('user')
      .where('user.login = :login', { login })
      .addSelect('user.password')
      .getOne();

    if (!userDB) {
      throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }

    const isValid = bcrypt.compareSync(password, userDB.password);
    if (!isValid) {
      throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }

    if (!userDB.isActive) {
      throw new AuthException(AuthErrorCode.USER_DISABLED);
    }

    return userDB;
  }

  async consumeAuthCode(code: string, clientId: string) {
    const payload: { userId: string; clientId: string } | undefined =
      await this.cacheManager.get(`authcode:${code}`);

    if (!payload) {
      throw new BadRequestException('Authorization code inválido o expirado');
    }

    if (payload.clientId !== clientId) {
      throw new UnauthorizedException('ClientId inválido para este code');
    }

    await this.cacheManager.del(`authcode:${code}`);

    return payload;
  }

  async refreshToken(dto: RefreshTokenDto) {
    const payload = await this.jwtService.verifyAsync<RefreshTokenPayload>(
      dto.refreshToken,
    );

    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
      relations: { accesses: true },
    });

    if (!user) throw new UnauthorizedException();

    return this.generateAuthTokens({
      sub: user.id,
      externalKey: user.externalKey,
      clientKey: payload.clientKey,
    });
  }

  private async generateAuthTokens(properties: GenerateTokenProperties) {
    const { sub, externalKey, clientKey } = properties;
    const accessToken = await this.jwtService.signAsync(
      { sub, externalKey, clientKey },
      { expiresIn: '1m' },
    );

    const refreshToken = await this.jwtService.signAsync(
      { sub, clientKey },
      { expiresIn: '1d' },
    );

    return { accessToken, refreshToken };
  }

  // 2️⃣ Obtener userId desde una sesión
  async getUserFromSession(sessionId: string) {
    return await this.cacheManager.get<string>(`session:${sessionId}`);
  }

  async savePendingOAuthRequest(data: PendingAuthRequest) {
    const oAuthRequestId = crypto.randomUUID();
    const key = `pending_oauth:${oAuthRequestId}`;
    await this.cacheManager.set(key, data, 300 * 1000);
    return oAuthRequestId;
  }

  async getOAuthRequest(oAuthRequestId: string) {
    const key = `pending_oauth:${oAuthRequestId}`;
    const data = await this.cacheManager.get<PendingAuthRequest>(key);
    return data ?? null;
  }

  async clearOAuthRequest(oauthLoginId: string): Promise<void> {
    const key = `pending_oauth:${oauthLoginId}`;
    await this.cacheManager.del(key);
  }

  async createSession(user: User): Promise<string> {
    const sessionId = crypto.randomUUID();
    const key = `session:${sessionId}`;
    await this.cacheManager.set(key, user.id, 24 * 60 * 60 * 1000);
    return sessionId;
  }

  async getSessionUser(sessionId: string): Promise<string | undefined> {
    return await this.cacheManager.get(`session:${sessionId}`);
  }

  async createAuthorizationContext(context: AuthorizationContext) {
    const code = crypto.randomUUID();
    await this.cacheManager.set(`authorization_context:${code}`, context, 300);
    return code;
  }

  async exchangeAuthorizationCode(params: TokenRequestDto) {
    const key = `authorization_context:${params.code}`;

    const context = await this.cacheManager.get<AuthorizationContext>(key);

    if (!context) {
      throw new UnauthorizedException('Invalid or expired authorization code');
    }

    if (context.clientId !== params.client_id) {
      throw new UnauthorizedException('Invalid client');
    }

    if (context.redirectUri !== params.redirect_uri) {
      throw new UnauthorizedException('Invalid redirect_uri');
    }

    await this.cacheManager.del(key);

    return await this.generateTokens({
      userId: context.userId,
      clientId: context.clientId,
    });
  }

  async generateTokens(payload: { userId: string; clientId: string }) {
    const access_token = await this.jwtService.signAsync(
      {
        sub: payload.userId,
        client: payload.clientId,
      },
      { expiresIn: '1m' },
    );

    const refresh_token = await this.jwtService.signAsync(
      {
        sub: payload.userId,
        client: payload.clientId,
        type: 'refresh',
      },
      { expiresIn: '1d' },
    );

    return { access_token, refresh_token };
  }

  async validateSession(sessionId: string) {
    const userId = await this.cacheManager.get<string>(`session:${sessionId}`);
    if (!userId) return null;
    const user = await this.userRepository.findOneBy({ id: userId });

    if (!user || !user.isActive) {
      return null;
    }

    // 4️⃣ Devolver usuario “limpio”
    return {
      id: user.id,
      fullName: user.fullName,
      roles: user.roles,
    };
  }

  async resolveLoginSuccessRedirect(user: User, params: LoginParamsDto) {
    const { auth_request_id } = params;

    if (!auth_request_id) return 'http://localhost:4200/apps';

    const oauthRequest = await this.getOAuthRequest(auth_request_id);

    if (!oauthRequest) return 'http://localhost:4200/apps';

    await this.clearOAuthRequest(auth_request_id);

    const code = await this.createAuthorizationContext({
      userId: user.id,
      clientId: oauthRequest.client_id,
      redirectUri: oauthRequest.redirect_uri,
    });

    const url = new URL(oauthRequest.redirect_uri);

    url.searchParams.set('code', code);

    if (oauthRequest.state) url.searchParams.set('state', oauthRequest.state);

    return url.toString();
  }

  resolveLoginErrorRedirect(error: AuthException, params: LoginParamsDto) {
    const { auth_request_id } = params;

    const url = new URL('http://localhost:4200/login');

    url.searchParams.set('error', error.code);

    if (auth_request_id) {
      url.searchParams.set('auth_request_id', auth_request_id);
    }

    return url.toString();
  }

  async handleAuthorize(query: AuthorizeParamsDto, sessionId?: string) {
    const { client_id, redirect_uri, state } = query;

    const userId = sessionId ? await this.getSessionUser(sessionId) : undefined;

    if (!userId) {
      const oAuthRequestId = await this.savePendingOAuthRequest({
        client_id,
        redirect_uri,
        state,
      });

      const loginUrl = new URL('http://localhost:4200/login');
      loginUrl.searchParams.set('auth_request_id', oAuthRequestId);

      return loginUrl.toString();
    }

    const code = await this.createAuthorizationContext({
      userId,
      clientId: client_id,
      redirectUri: redirect_uri,
    });

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (state) redirectUrl.searchParams.set('state', state);

    return redirectUrl.toString();
  }
}
