const data = new Map<string, string>();
export const SecureStoragePlugin = {
  async get({ key }: { key: string }) {
    if (!data.has(key)) throw new Error('Item with given key does not exist');
    return { value: data.get(key)! };
  },
  async set({ key, value }: { key: string; value: string }) {
    data.set(key, value);
  },
  async remove({ key }: { key: string }) {
    data.delete(key);
  },
  async keys() {
    return { value: [...data.keys()] };
  },
};
