import { json, redirect } from '@sveltejs/kit';
import type { RequestEvent } from "@sveltejs/kit";
import { createKindeStorage } from '$lib/kindeCloudflareStorage';
import { KINDE_ISSUER_URL, KINDE_CLIENT_ID, KINDE_CLIENT_SECRET, KINDE_REDIRECT_URL, KINDE_POST_LOGIN_REDIRECT_URL, KINDE_POST_LOGOUT_REDIRECT_URL, KINDE_SCOPE, KINDE_AUTH_WITH_PKCE } from '$env/static/private';
// Get environment variable

export async function GET(event: RequestEvent) {
  const storage = createKindeStorage(event);
  const url = new URL(event.request.url);
  const path = url.pathname.split('/').pop() || '';
  
  console.log(`Auth request: ${path}`, {
    hasStorage: !!storage,
    hasState: !!url.searchParams.get('state'),
    hasCode: !!url.searchParams.get('code')
  });
  
  if (!storage) {
    console.error('KV storage not available');
    return json({ error: 'KV storage not available' }, { status: 500 });
  }
  
  // Handle various auth endpoints
  switch (path) {
    case 'login':
      return handleLogin(event, storage, false);
    
    case 'register':
      return handleLogin(event, storage, true);
    
    case 'kinde_callback':
      return handleCallback(event, storage);
    
    case 'logout':
      return handleLogout(event, storage);
    
    default:
      return json({ error: 'Unknown auth endpoint' }, { status: 404 });
  }
}

// Generate crypto-secure random string for state
function generateRandomString(length = 32) {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let text = '';
  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

// Add this at the top of your file
async function sha256(plain: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return await crypto.subtle.digest('SHA-256', data);
}

function base64URLEncode(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Handle login or registration
async function handleLogin(event: RequestEvent, storage: any, isRegister: boolean) {
  // Generate state parameter
  const state = generateRandomString(24);
  
  // For PKCE, generate code challenge
  let codeVerifier: string | undefined;
  let codeChallenge: string | undefined;
  
  if (KINDE_AUTH_WITH_PKCE) {
    codeVerifier = generateRandomString(64);
    
    // Create proper code challenge with SHA-256
    const challengeBuffer = await sha256(codeVerifier);
    codeChallenge = base64URLEncode(challengeBuffer);
  }
  
  // Store state (and code verifier if using PKCE)
  await storage.setState(state, codeVerifier || 'true');
  
  // Get additional parameters from URL
  const url = new URL(event.request.url);
  const orgCode = url.searchParams.get('org_code');
  const postLoginRedirect = url.searchParams.get('post_login_redirect_url') || KINDE_POST_LOGIN_REDIRECT_URL;
  
  // Build auth URL
  const authUrl = new URL(isRegister ? '/oauth2/auth/register' : '/oauth2/auth', KINDE_ISSUER_URL);
  
  // Add standard OAuth parameters
  authUrl.searchParams.append('client_id', KINDE_CLIENT_ID);
  authUrl.searchParams.append('redirect_uri', KINDE_REDIRECT_URL);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', KINDE_SCOPE);
  authUrl.searchParams.append('state', state);
  
  // Add optional parameters
  if (orgCode) {
    authUrl.searchParams.append('org_code', orgCode);
  }
  
  // Store post-login redirect
  await storage.setState(`redirect:${state}`, postLoginRedirect);
  
  // Add PKCE parameters if enabled
  if (KINDE_AUTH_WITH_PKCE && codeChallenge) {
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
  }
  
  // Redirect to Kinde auth URL
  console.log(`Redirecting to Kinde auth: ${authUrl.toString()}`);
  return redirect(302, authUrl.toString());
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
    return json({ error: 'Missing code or state parameter' }, { status: 400 });
  }
  
  // Verify state parameter
  const storedState = await storage.getState(state);
  if (!storedState) {
    console.error('State not found:', state);
    
    // Store error for debugging
    await storage.setState('last_error', {
      time: new Date().toISOString(),
      error: 'State not found',
      state
    });
    
    return json({ error: 'Invalid state parameter' }, { status: 401 });
  }
  
  // Get code verifier for PKCE if it exists
  const codeVerifier = storedState === 'true' ? undefined : storedState;
  
  // Get post-login redirect URL
  const redirectUrl = await storage.getState(`redirect:${state}`) || KINDE_POST_LOGIN_REDIRECT_URL;
  
  // Clean up stored state
  await storage.deleteState(state);
  await storage.deleteState(`redirect:${state}`);
  
  try {
    // Exchange code for tokens
    const tokenResponse = await fetchTokens(code, codeVerifier);
    
    // Store tokens in KV storage
    await storage.setState('tokens', {
      access_token: tokenResponse.access_token,
      refresh_token: tokenResponse.refresh_token || null,
      id_token: tokenResponse.id_token || null,
      expires_in: tokenResponse.expires_in || 3600,
      timestamp: Date.now()
    });
    
    console.log('Tokens stored successfully');
    
    // Log the redirect URL for debugging
    console.log('Redirecting to:', redirectUrl);
    
    // Create a redirect response with proper headers
    return new Response(null, {
      status: 302,
      headers: {
        'Location': redirectUrl,
        'Cache-Control': 'no-store'
      }
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error('Token exchange error:', errorMessage);
    
    // Store error for debugging
    await storage.setState('token_error', {
      time: new Date().toISOString(),
      error: safeStringify(error)
    });
    
    return json({ error: 'Token exchange failed' }, { status: 500 });
  }
}

// Exchange authorization code for tokens
async function fetchTokens(code: string, codeVerifier?: string) {
  const tokenUrl = new URL('/oauth2/token', KINDE_ISSUER_URL);
  const params = new URLSearchParams();
  
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', KINDE_REDIRECT_URL);
  params.append('client_id', KINDE_CLIENT_ID);
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
  };
  
  // Check if we're using PKCE
  if (KINDE_AUTH_WITH_PKCE && codeVerifier && codeVerifier !== 'true') {
    console.log('Using PKCE flow with code verifier');
    params.append('code_verifier', codeVerifier);
    // Do not include client_secret for PKCE flow
  } else {
    console.log('Using authorization code flow with client secret');
    const clientSecret = KINDE_CLIENT_SECRET || 'W0PV642CRqIptpSAvtZB6euWf2tgxQhKYJUFzYZKo4Z8oGm8wW';
    params.append('client_secret', clientSecret);
  }
  
  // Log the request details (without sensitive info)
  console.log('Token exchange request:', {
    url: tokenUrl.toString(),
    isPKCE: KINDE_AUTH_WITH_PKCE && codeVerifier && codeVerifier !== 'true',
    hasClientSecret: !KINDE_AUTH_WITH_PKCE || (codeVerifier === 'true' || !codeVerifier)
  });
  
  try {
    const response = await fetch(tokenUrl.toString(), {
      method: 'POST',
      headers,
      body: params
    });
    
    const responseText = await response.text();
    console.log('Token response status:', response.status);
    
    // Try to parse the response as JSON
    let responseData;
    try {
      responseData = JSON.parse(responseText);
      console.log('Token response parsed successfully');
    } catch (parseError) {
      console.error('Failed to parse token response as JSON:', responseText);
      throw new Error(`Invalid JSON response: ${responseText}`);
    }
    
    // Check for errors in the response
    if (!response.ok) {
      console.error('Token exchange error details:', {
        status: response.status,
        error: responseData.error,
        description: responseData.error_description
      });
      
      throw new Error(`Token exchange failed: ${response.status} - ${responseData.error}: ${responseData.error_description}`);
    }
    
    // Check if the response has the expected tokens
    if (!responseData.access_token) {
      console.error('Token response missing access_token:', responseData);
      throw new Error('Token response missing required fields');
    }
    
    // Log success
    console.log('Token exchange successful');
    
    return responseData;
  } catch (error) {
    console.error('Token exchange error:', error instanceof Error ? error.message : 'Unknown error');
    throw error;
  }
}

// Handle logout
async function handleLogout(event: RequestEvent, storage: any) {
  // Clear tokens from KV storage
  await storage.deleteState('tokens');
  console.log('Tokens deleted during logout');
  
  // Redirect to Kinde's logout endpoint
  const logoutUrl = new URL('/logout', KINDE_ISSUER_URL);
  logoutUrl.searchParams.append('redirect', KINDE_POST_LOGOUT_REDIRECT_URL);
  
  return redirect(302, logoutUrl.toString());
}

// Helper function to safely stringify errors
function safeStringify(obj: any): string {
  try {
    if (obj instanceof Error) {
      return obj.message + (obj.stack ? `\n${obj.stack}` : '');
    }
    
    return JSON.stringify(obj);
  } catch (e) {
    return `[Unstringifiable object: ${typeof obj}]`;
  }
} 