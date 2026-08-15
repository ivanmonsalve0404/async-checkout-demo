import type { ReactNode } from 'react';
import { Provider } from 'react-redux';
import { BrowserRouter } from 'react-router-dom';
import { createAppStore } from '../store/store';

const store = createAppStore();

export const AppProviders = ({ children }: Readonly<{ children: ReactNode }>) => (
  <Provider store={store}>
    <BrowserRouter>{children}</BrowserRouter>
  </Provider>
);
