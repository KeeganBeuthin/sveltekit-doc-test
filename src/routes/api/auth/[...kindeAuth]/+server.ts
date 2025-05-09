import { json, redirect } from '@sveltejs/kit';
import type { RequestEvent } from "@sveltejs/kit";
import { createKindeStorage } from '$lib/kindeCloudflareStorage';

// These MUST be defined in your environment variables
const ISSUER_URL = context.env.KINDE_ISSUER_URL || '';
const CLIENT_ID = context.env.KINDE_CLIENT_ID || '';
const CLIENT_SECRET = context.env.KINDE_CLIENT_SECRET || '';
const REDIRECT_URL = context.env.KINDE_REDIRECT_URL || '';
const POST_LOGIN_REDIRECT_URL = context.env.KINDE_POST_LOGIN_REDIRECT_URL || '/dashboard';
const POST_LOGOUT_REDIRECT_URL = context.env.KINDE_POST_LOGOUT_REDIRECT_URL || '/';
const SCOPE = context.env.KINDE_SCOPE || 'openid profile email offline';

export async function GET(event: RequestEvent) {
  const storage = createKindeStorage(event);
  const url = new URL(event.request.url);
  const path = url.pathname.split('/').pop() || '';
  
  if (!storage) {
    console.error('KV storage not available');
    return json({ error: 'KV storage not available' }, { status: 500 });
  }
  
  // Handle various auth endpoints
  switch (path) {
    case 'login':
      return handleLogin(event, storage);
    case 'kinde_callback':
      return handleCallback(event, storage);
    case 'logout':
      return handleLogout(event, storage);
    default:
      return json({ error: 'Unknown auth endpoint' }, { status: 404 });
  }
}

// Generate secure random string for state
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
  // Validate required environment variables
  if (!ISSUER_URL || !CLIENT_ID || !REDIRECT_URL) {
    console.error('Missing required environment variables');
    return json({ error: 'Missing configuration' }, { status: 500 });
  }

  // Generate and store state
  const state = generateRandomString(24);
  await storage.setState(state, 'true');
  
  // Store redirect URL
  await storage.setState(`redirect:${state}`, POST_LOGIN_REDIRECT_URL);
  
  try {
    // Build authorization URL - ensure ISSUER_URL is valid
    const authUrl = new URL('/oauth2/auth', ISSUER_URL);
    authUrl.searchParams.append('client_id', CLIENT_ID);
    authUrl.searchParams.append('redirect_uri', REDIRECT_URL);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', SCOPE);
    authUrl.searchParams.append('state', state);
    
    console.log(`Redirecting to Kinde auth: ${authUrl.toString()}`);
    return redirect(302, authUrl.toString());
  } catch (error) {
    console.error('Error creating authorization URL:', error);
    return json({ error: 'Invalid configuration' }, { status: 500 });
  }
}

// Handle OAuth callback
async function handleCallback(event: RequestEvent, storage: any) {
  const url = new URL(event.request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');
  
  // Check for OAuth errors
  if (error) {
    console.error('OAuth error:', error);
    return json({ error: `OAuth error: ${error}` }, { status: 400 });
  }
  
  // Validate required parameters
  if (!code || !state) {
    console.error('Missing code or state parameter');
    return json({ error: 'Missing required parameters' }, { status: 400 });
  }
  
  // Verify state parameter
  const storedState = await storage.getState(state);
  if (!storedState) {
    console.error('State not found:', state);
    return json({ error: 'Invalid state parameter' }, { status: 401 });
  }
  
  // Get post-login redirect URL
  const redirectUrl = await storage.getState(`redirect:${state}`) || POST_LOGIN_REDIRECT_URL;
  
  // Clean up stored state
  await storage.deleteState(state);
  await storage.deleteState(`redirect:${state}`);
  
  try {
    // Exchange code for tokens
    if (!ISSUER_URL || !CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URL) {
      throw new Error('Missing required environment variables');
    }
    
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
      const errorBody = await response.text();
      console.error('Token exchange error:', errorBody);
      throw new Error(`Token exchange failed: ${response.status}`);
    }
    
    const tokens = await response.json();
    
    if (!tokens.access_token) {
      throw new Error('Token response missing required fields');
    }
    
    // Store tokens
    await storage.setState('tokens', {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token || null,
      id_token: tokens.id_token || null,
      expires_in: tokens.expires_in || 3600,
      timestamp: Date.now()
    });
    
    console.log('Tokens stored successfully');
    
    // Redirect to application
    return new Response(null, {
      status: 302,
      headers: {
        'Location': redirectUrl,
        'Cache-Control': 'no-store'
      }
    });
  } catch (error) {
    console.error('Token exchange error:', error instanceof Error ? error.message : 'Unknown error');
    return json({ error: 'Token exchange failed' }, { status: 500 });
  }
}

// Handle logout
async function handleLogout(event: RequestEvent, storage: any) {
  // Clear tokens
  await storage.deleteState('tokens');
  console.log('Tokens deleted during logout');
  
  try {
    // Redirect to Kinde logout
    if (!ISSUER_URL) {
      throw new Error('Missing ISSUER_URL environment variable');
    }
    
    const logoutUrl = new URL('/logout', ISSUER_URL);
    logoutUrl.searchParams.append('redirect', POST_LOGOUT_REDIRECT_URL);
    
    return redirect(302, logoutUrl.toString());
  } catch (error) {
    console.error('Logout error:', error);
    return redirect(302, POST_LOGOUT_REDIRECT_URL);
  }
}