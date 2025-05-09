import type { RequestEvent } from '@sveltejs/kit';

export const createKindeStorage = (event: RequestEvent) => {
  const platform = event.platform as any;
  const env = platform?.env;
  const AUTH_STORAGE = env?.AUTH_STORAGE;

  if (!AUTH_STORAGE) {
    return null;
  }

  return {
    setState: async (stateId: string, stateData: any) => {
      try {
        const key = `kinde:state:${stateId}`;
        const value = typeof stateData === 'string'
          ? stateData
          : JSON.stringify(stateData);

        await AUTH_STORAGE.put(key, value, { expirationTtl: 600 });
        return true;
      } catch (error) {
        return false;
      }
    },

    getState: async (stateId: string) => {
      try {
        const key = `kinde:state:${stateId}`;
        const value = await AUTH_STORAGE.get(key);

        if (!value) return null;

        try {
          return JSON.parse(value);
        } catch {
          return value;
        }
      } catch (error) {
        return null;
      }
    },

    deleteState: async (stateId: string) => {
      try {
        const key = `kinde:state:${stateId}`;
        await AUTH_STORAGE.delete(key);
        return true;
      } catch (error) {
        return false;
      }
    }
  };
};