import { json, redirect } from '@sveltejs/kit';
import type { RequestEvent } from "@sveltejs/kit";
import { createKindeStorage } from '$lib/kindeCloudflareStorage';

// Helper function for login and registration
async function handleLogin(
  issuerUrl: string,
  clientId: string,
  redirectUrl: string,
  scope: string,
  postLoginUrl: string,
  usePkce: boolean,
  event: RequestEvent,
  storage: any,
  isRegister: boolean
) {
  // Generate a random state parameter
  const state = crypto.randomUUID();
  
  // Store the state and post-login URL
  await storage.setState(state, { postLoginUrl });
  
  // Generate code verifier and challenge if using PKCE
  let codeVerifier;
  let codeChallenge;
  
  if (usePkce) {
    codeVerifier = crypto.randomUUID() + crypto.randomUUID();
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    
    await storage.setState('code_verifier', codeVerifier);
  }
  
  // Construct the authorization URL
  const authUrl = new URL(`${issuerUrl}/oauth2/auth`);
  authUrl.searchParams.append('client_id', clientId);
  authUrl.searchParams.append('redirect_uri', redirectUrl);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', scope);
  authUrl.searchParams.append('state', state);
  
  if (isRegister) {
    authUrl.searchParams.append('is_register', 'true');
  }
  
  if (usePkce) {
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
  }
  
  return redirect(302, authUrl.toString());
}

// Handle callback from Kinde
async function handleCallback(
  issuerUrl: string,
  clientId: string,
  clientSecret: string,
  redirectUrl: string,
  usePkce: boolean,
  event: RequestEvent,
  storage: any
) {
  const url = new URL(event.request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  
  if (!code || !state) {
    return json({ error: 'Invalid callback parameters' }, { status: 400 });
  }
  
  // Retrieve the state data
  const stateData = await storage.getState(state);
  if (!stateData) {
    return json({ error: 'Invalid state parameter' }, { status: 400 });
  }
  
  // Prepare token exchange parameters
  const tokenParams = new URLSearchParams();
  tokenParams.append('grant_type', 'authorization_code');
  tokenParams.append('client_id', clientId);
  tokenParams.append('redirect_uri', redirectUrl);
  tokenParams.append('code', code);
  
  if (usePkce) {
    const codeVerifier = await storage.getState('code_verifier');
    if (!codeVerifier) {
      return json({ error: 'Code verifier not found' }, { status: 400 });
    }
    tokenParams.append('code_verifier', codeVerifier);
    await storage.deleteState('code_verifier');
  } else {
    tokenParams.append('client_secret', clientSecret);
  }
  
  // Exchange the code for tokens
  try {
    const tokenResponse = await fetch(`${issuerUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: tokenParams.toString()
    });
    
    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      return json({ error: `Token exchange failed: ${error}` }, { status: 400 });
    }
    
    const tokens = await tokenResponse.json();
    
    // Store the tokens
    await storage.setState('tokens', tokens);
    
    // Redirect to the post-login URL
    const redirectTo = stateData.postLoginUrl || '/';
    await storage.deleteState(state);
    
    return redirect(302, redirectTo);
  } catch (error) {
    console.error('Token exchange error:', error);
    return json({ error: 'Token exchange failed' }, { status: 500 });
  }
}

// Handle logout
async function handleLogout(
  issuerUrl: string,
  clientId: string,
  postLogoutUrl: string,
  event: RequestEvent,
  storage: any
) {
  // Clear tokens
  await storage.deleteState('tokens');
  
  // Construct logout URL
  const logoutUrl = new URL(`${issuerUrl}/logout`);
  logoutUrl.searchParams.append('client_id', clientId);
  
  if (postLogoutUrl) {
    logoutUrl.searchParams.append('redirect_uri', postLogoutUrl);
  }
  
  return redirect(302, logoutUrl.toString());
}

export async function GET(event: RequestEvent) {
  // Get environment variables from platform
  const platform = event.platform as any;
  const env = platform?.env;

  // Simplified config access
  const config = {
    issuerUrl: env?.KINDE_ISSUER_URL || process.env.KINDE_ISSUER_URL,
    clientId: env?.KINDE_CLIENT_ID || process.env.KINDE_CLIENT_ID,
    clientSecret: env?.KINDE_CLIENT_SECRET || process.env.KINDE_CLIENT_SECRET,
    redirectUrl: env?.KINDE_REDIRECT_URL || process.env.KINDE_REDIRECT_URL,
    postLoginUrl: env?.KINDE_POST_LOGIN_REDIRECT_URL || process.env.KINDE_POST_LOGIN_REDIRECT_URL,
    postLogoutUrl: env?.KINDE_POST_LOGOUT_REDIRECT_URL || process.env.KINDE_POST_LOGOUT_REDIRECT_URL,
    scope: 'openid profile email offline',
    usePkce: (env?.KINDE_AUTH_WITH_PKCE || process.env.KINDE_AUTH_WITH_PKCE) === 'true'
  };

  const storage = createKindeStorage(event);
  const path = new URL(event.request.url).pathname.split('/').pop() || '';

  if (!storage) {
    return json({ error: 'KV storage not available' }, { status: 500 });
  }

  // Handle authentication routes
  switch (path) {
    case 'login':
      return handleLogin(config.issuerUrl, config.clientId, config.redirectUrl,
                        config.scope, config.postLoginUrl, config.usePkce,
                        event, storage, false);
    case 'register':
      return handleLogin(config.issuerUrl, config.clientId, config.redirectUrl,
                        config.scope, config.postLoginUrl, config.usePkce,
                        event, storage, true);
    case 'kinde_callback':
      return handleCallback(config.issuerUrl, config.clientId, config.clientSecret,
                          config.redirectUrl, config.usePkce, event, storage);
    case 'logout':
      return handleLogout(config.issuerUrl, config.clientId, config.postLogoutUrl,
                         event, storage);
    default:
      return json({ error: 'Unknown auth endpoint' }, { status: 404 });
  }
} 