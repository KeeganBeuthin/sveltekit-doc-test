import { json, redirect } from '@sveltejs/kit';
import type { RequestEvent } from "@sveltejs/kit";
import { createKindeStorage } from '$lib/kindeCloudflareStorage';

// Environment variables
const ISSUER_URL = process.env.KINDE_ISSUER_URL;
const CLIENT_ID = process.env.KINDE_CLIENT_ID;
const CLIENT_SECRET = process.env.KINDE_CLIENT_SECRET;
const REDIRECT_URL = process.env.KINDE_REDIRECT_URL;
const POST_LOGIN_REDIRECT_URL = process.env.KINDE_POST_LOGIN_REDIRECT_URL || '/dashboard';
const POST_LOGOUT_REDIRECT_URL = process.env.KINDE_POST_LOGOUT_REDIRECT_URL || '/';
const SCOPE = process.env.KINDE_SCOPE || 'openid profile email offline';

export async function GET(event: RequestEvent) {
  const storage = createKindeStorage(event);
  if (!storage) {
    return json({ error: 'KV storage not available' }, { status: 500 });
  }
  
  const url = new URL(event.request.url);
  const path = url.pathname.split('/').pop() || '';
  
  switch (path) {
    case 'login': return handleLogin(event, storage);
    case 'kinde_callback': return handleCallback(event, storage);
    case 'logout': return handleLogout(event, storage);
    default: return json({ error: 'Unknown endpoint' }, { status: 404 });
  }
}

// Generate a secure random string for state
function generateRandomString(length = 32) {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let text = '';
  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

// Handle login request
async function handleLogin(event: RequestEvent, storage: any) {
  // Generate and store state
  const state = generateRandomString(24);
  await storage.setState(state, 'true');
  
  // Store redirect URL
  const postLoginRedirect = POST_LOGIN_REDIRECT_URL;
  await storage.setState(`redirect:${state}`, postLoginRedirect);
  
  // Build authorization URL
  const authUrl = new URL('/oauth2/auth', ISSUER_URL);
  authUrl.searchParams.append('client_id', CLIENT_ID);
  authUrl.searchParams.append('redirect_uri', REDIRECT_URL);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', SCOPE);
  authUrl.searchParams.append('state', state);
  
  return redirect(302, authUrl.toString());
}

// Handle OAuth callback
async function handleCallback(event: RequestEvent, storage: any) {
  const url = new URL(event.request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  
  // Validate parameters
  if (!code || !state) {
    return json({ error: 'Missing required parameters' }, { status: 400 });
  }
  
  // Verify state
  const storedState = await storage.getState(state);
  if (!storedState) {
    return json({ error: 'Invalid state parameter' }, { status: 401 });
  }
  
  // Get redirect URL
  const redirectUrl = await storage.getState(`redirect:${state}`) || POST_LOGIN_REDIRECT_URL;
  
  // Clean up state
  await storage.deleteState(state);
  await storage.deleteState(`redirect:${state}`);
  
  try {
    // Exchange code for tokens
    const tokenUrl = new URL('/oauth2/token', ISSUER_URL);
    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', REDIRECT_URL);
    params.append('client_id', CLIENT_ID);
    params.append('client_secret', CLIENT_SECRET);
    
    const response = await fetch(tokenUrl.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: params
    });
    
    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.status}`);
    }
    
    const tokens = await response.json();
    
    // Store tokens
    await storage.setState('tokens', {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token || null,
      id_token: tokens.id_token || null,
      expires_in: tokens.expires_in || 3600,
      timestamp: Date.now()
    });
    
    // Redirect to application
    return new Response(null, {
      status: 302,
      headers: {
        'Location': redirectUrl,
        'Cache-Control': 'no-store'
      }
    });
  } catch (error) {
    return json({ error: 'Token exchange failed' }, { status: 500 });
  }
}

// Handle logout
async function handleLogout(event: RequestEvent, storage: any) {
  // Clear tokens
  await storage.deleteState('tokens');
  
  // Redirect to Kinde logout
  const logoutUrl = new URL('/logout', ISSUER_URL);
  logoutUrl.searchParams.append('redirect', POST_LOGOUT_REDIRECT_URL);
  
  return redirect(302, logoutUrl.toString());
}