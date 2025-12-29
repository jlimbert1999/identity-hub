export interface PendingAuthRequest {
  client_id: string;
  redirect_uri: string;
  state: string;
}
