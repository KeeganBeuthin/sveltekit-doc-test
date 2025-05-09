// src/lib/kindeCloudflareStorage.ts
import type { RequestEvent } from '@sveltejs/kit';

export const createKindeStorage = (event: RequestEvent) => {
  const platform = event.platform as any;
  const env = platform?.env;
  const AUTH_STORAGE = env?.AUTH_STORAGE;
  
  if (!AUTH_STORAGE) {
    console.error('KV storage not available for Kinde state management');
    return null;
  }
  
  return {
    // Store OAuth state and code verifier
    setState: async (stateId: string, stateData: any) => {
      try {
        // Store with namespace to avoid conflicts
        const key = `kinde:state:${stateId}`;
        
        // Convert data to string if needed
        const value = typeof stateData === 'string' 
          ? stateData 
          : JSON.stringify(stateData);
        
        // Add expiration (10 minutes is typically sufficient for auth flow)
        await AUTH_STORAGE.put(key, value, { expirationTtl: 600 });
        
        console.log(`State stored: ${stateId}`);
        return true;
      } catch (error) {
        console.error('Failed to save Kinde state:', error);
        return false;
      }
    },
    
    // Retrieve state data
    getState: async (stateId: string) => {
      try {
        const key = `kinde:state:${stateId}`;
        const value = await AUTH_STORAGE.get(key);
        
        console.log(`State retrieved: ${stateId}`, !!value);
        
        if (!value) return null;
        
        // Try parsing as JSON, fallback to string value
        try {
          return JSON.parse(value);
        } catch {
          return value;
        }
      } catch (error) {
        console.error('Failed to get Kinde state:', error);
        return null;
      }
    },
    
    // Remove state after use
    deleteState: async (stateId: string) => {
      try {
        const key = `kinde:state:${stateId}`;
        await AUTH_STORAGE.delete(key);
        console.log(`State deleted: ${stateId}`);
        return true;
      } catch (error) {
        console.error('Failed to delete Kinde state:', error);
        return false;
      }
    }
  };
};