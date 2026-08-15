import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

export const checkoutSteps = ['payment', 'customer', 'acceptances', 'review', 'status'] as const;
export type CheckoutStep = (typeof checkoutSteps)[number];

export interface CheckoutUiState {
  checkoutId: string | undefined;
  transactionId: string | undefined;
  idempotencyKey: string | undefined;
  step: CheckoutStep;
  modalOpen: boolean;
  returnNotice: 'APPROVED' | 'FAILED' | undefined;
}

export const initialCheckoutState: CheckoutUiState = {
  checkoutId: undefined,
  transactionId: undefined,
  idempotencyKey: undefined,
  step: 'payment',
  modalOpen: false,
  returnNotice: undefined,
};

const checkoutSlice = createSlice({
  name: 'checkoutUi',
  initialState: initialCheckoutState,
  reducers: {
    openCheckout: (state) => {
      state.modalOpen = true;
    },
    closeCheckout: (state) => {
      state.modalOpen = false;
    },
    checkoutCreated: (
      state,
      action: PayloadAction<{ checkoutId: string; idempotencyKey: string }>,
    ) => {
      state.checkoutId = action.payload.checkoutId;
      state.idempotencyKey = action.payload.idempotencyKey;
      state.transactionId = undefined;
      state.step = 'payment';
      state.modalOpen = true;
    },
    checkoutRecovered: (
      state,
      action: PayloadAction<{
        checkoutId: string;
        transactionId?: string;
        idempotencyKey?: string;
      }>,
    ) => {
      state.checkoutId = action.payload.checkoutId;
      state.transactionId = action.payload.transactionId;
      state.idempotencyKey =
        action.payload.transactionId === undefined ? action.payload.idempotencyKey : undefined;
      state.step = action.payload.transactionId === undefined ? 'payment' : 'status';
      state.modalOpen = true;
    },
    stepChanged: (state, action: PayloadAction<CheckoutStep>) => {
      state.step = action.payload;
    },
    transactionAccepted: (state, action: PayloadAction<string>) => {
      state.transactionId = action.payload;
      state.step = 'status';
    },
    attemptRestarted: (state, action: PayloadAction<string>) => {
      state.transactionId = undefined;
      state.idempotencyKey = action.payload;
      state.step = 'payment';
    },
    progressCleared: (state) => {
      state.checkoutId = undefined;
      state.transactionId = undefined;
      state.idempotencyKey = undefined;
      state.step = 'payment';
      state.modalOpen = false;
    },
    returnedToProduct: (state, action: PayloadAction<'APPROVED' | 'FAILED'>) => {
      state.checkoutId = undefined;
      state.transactionId = undefined;
      state.idempotencyKey = undefined;
      state.step = 'payment';
      state.modalOpen = false;
      state.returnNotice = action.payload;
    },
    returnNoticeCleared: (state) => {
      state.returnNotice = undefined;
    },
  },
});

export const {
  attemptRestarted,
  checkoutCreated,
  checkoutRecovered,
  closeCheckout,
  openCheckout,
  progressCleared,
  returnedToProduct,
  returnNoticeCleared,
  stepChanged,
  transactionAccepted,
} = checkoutSlice.actions;

export const checkoutReducer = checkoutSlice.reducer;

export const createIdempotencyKey = (): string => {
  const bytes = new Uint8Array(18);
  globalThis.crypto.getRandomValues(bytes);
  return 'idem_' + Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
};
