import type { PageServerLoad } from './$types';
import { createKindeStorage } from '$lib/kindeCloudflareStorage';

export const load: PageServerLoad = async (event) => {
  const storage = createKindeStorage(event);
  
  if (!storage) {
    return {
      authenticated: false,
      error: 'Storage not available'
    };
  }
  
  try {
    // Check if we have tokens
    const tokens = await storage.getState('tokens');
    const isAuthenticated = !!tokens?.access_token;
    
    // IMPORTANT: Do NOT redirect here, just return the authentication state
    return {
      authenticated: isAuthenticated
    };
  } catch (error) {
    console.error('Error checking authentication:', error);
    return {
      authenticated: false,
      error: 'Error checking authentication'
    };
  }
}; 