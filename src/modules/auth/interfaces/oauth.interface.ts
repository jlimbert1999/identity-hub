export interface AuthorizationCodePayload {
  userId: string;
  fullName: string;
  externalKey: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
}
