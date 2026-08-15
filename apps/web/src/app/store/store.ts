import { configureStore } from '@reduxjs/toolkit';
import { useDispatch, useSelector } from 'react-redux';
import { baseApi } from '../api/base-api';
import {
  browserProgressStores,
  persistCheckoutProgress,
  readCheckoutProgress,
  type ProgressStores,
} from '../../features/checkout/model/checkout-storage';
import {
  checkoutReducer,
  initialCheckoutState,
} from '../../features/checkout/model/checkout-slice';

export const createAppStore = (stores = browserProgressStores()) => {
  const checkout =
    stores === undefined ? { ...initialCheckoutState } : readCheckoutProgress(stores);
  const store = configureStore({
    reducer: {
      [baseApi.reducerPath]: baseApi.reducer,
      checkout: checkoutReducer,
    },
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(baseApi.middleware),
    preloadedState: { checkout },
    devTools: false,
  });
  if (stores !== undefined) {
    store.subscribe(() => {
      persistCheckoutProgress(store.getState().checkout, stores);
    });
  }
  return store;
};

export type AppStore = ReturnType<typeof createAppStore>;
export type RootState = ReturnType<AppStore['getState']>;
export type AppDispatch = AppStore['dispatch'];

export const useAppDispatch = useDispatch.withTypes<AppDispatch>();
export const useAppSelector = useSelector.withTypes<RootState>();

export type { ProgressStores };
