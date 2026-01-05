export class AccessTokenPayload {
  sub: string;
  clientId: string;
  scope?: string;
}
export interface RefreshTokenCache extends AccessTokenPayload {
  active: boolean;
}
