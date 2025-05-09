import { kindeAuthClient, type SessionManager } from '@kinde-oss/kinde-auth-sveltekit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ request }) => {
  const isAuthenticated = await kindeAuthClient.isAuthenticated(
    request as unknown as SessionManager
  );
  
  let user = null;
  if (isAuthenticated) {
    user = await kindeAuthClient.getUser(request as unknown as SessionManager);
  }
  
  return {
    isAuthenticated,
    user
  };
}; 