import { kindeAuthClient, type SessionManager } from '@kinde-oss/kinde-auth-sveltekit';
import type { LayoutServerLoad } from './$types';
import { createKindeStorage } from '$lib/kindeCloudflareStorage';

export const load: LayoutServerLoad = async (event) => {
  const storage = createKindeStorage(event);
  
  if (!storage) {
    return {
      authenticated: false
    };
  }
  
  try {
    // Check if we have tokens
    const tokens = await storage.getState('tokens');
    const isAuthenticated = !!tokens?.access_token;
    
    return {
      authenticated: isAuthenticated
    };
  } catch (error) {
    console.error('Error checking authentication:', error);
    return {
      authenticated: false
    };
  }
}; 