export interface PendingAuthRequest {
  client_id: string;
  redirect_uri: string;
  state: string;
}

export interface AuthorizationCodePayload {
  userId: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
}
