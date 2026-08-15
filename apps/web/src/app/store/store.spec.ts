import { baseApi } from '../api/base-api';
import { createAppStore } from './store';

describe('application store', () => {
  it('registers the central RTK Query reducer and middleware', () => {
    const store = createAppStore();
    expect(store.getState()).toHaveProperty(baseApi.reducerPath);
    expect(() => store.dispatch(baseApi.util.resetApiState())).not.toThrow();
  });
});
