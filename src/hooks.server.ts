import { sessionHooks, type Handler } from '@kinde-oss/kinde-auth-sveltekit';
import { createKindeStorage } from '$lib/kindeCloudflareStorage';

export const handle: Handler = async ({ event, resolve }) => {
  const storage = createKindeStorage(event);

  sessionHooks({
    event,
    ...(storage ? { storage } : {})
  });

  return await resolve(event);
}; 