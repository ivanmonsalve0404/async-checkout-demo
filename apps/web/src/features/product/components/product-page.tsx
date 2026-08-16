import { useNavigate } from 'react-router-dom';
import { useAppSelector } from '../../../app/store/store';
import { CheckoutDialog } from '../../checkout/components/checkout-dialog';
import { checkoutRoutes } from '../../checkout/testing-contract';
import { useGetProductQuery, type ProductResponse } from '../api/product-api';
import { ProductView, type ProductViewState } from './product-view';

export interface ProductQueryState {
  readonly isLoading: boolean;
  readonly data: ProductResponse | undefined;
  readonly error: unknown;
  readonly refetch: () => unknown;
}

export type ProductPageMode = 'product' | 'capture' | 'status';

const readErrorStatus = (error: unknown): number | string | undefined => {
  if (typeof error !== 'object' || error === null || !('status' in error)) {
    return undefined;
  }
  const { status } = error;
  return typeof status === 'number' || typeof status === 'string' ? status : undefined;
};

export const toViewState = (query: ProductQueryState): ProductViewState => {
  if (query.isLoading) {
    return { kind: 'loading' };
  }
  if (query.data !== undefined) {
    return { kind: 'success', product: query.data };
  }
  const errorStatus = readErrorStatus(query.error);
  if (errorStatus === 404) {
    return { kind: 'not-found' };
  }
  if (errorStatus === 'FETCH_ERROR' || errorStatus === 'TIMEOUT_ERROR') {
    return {
      kind: 'recoverable-error',
      retry: () => {
        void query.refetch();
      },
    };
  }
  return { kind: 'unrecoverable-error' };
};

export const ProductPage = ({
  productId,
  mode = 'product',
}: Readonly<{ productId: string; mode?: ProductPageMode }>) => {
  const navigate = useNavigate();
  const query = useGetProductQuery(productId);
  const progress = useAppSelector((state) => state.checkout);
  const hasProgress = progress.checkoutId !== undefined;
  const openProgress = (): void => {
    void navigate(
      progress.transactionId === undefined
        ? checkoutRoutes.capture(productId)
        : checkoutRoutes.status(productId),
    );
  };
  const backToProduct = (): void => {
    void navigate(checkoutRoutes.product(productId), { replace: true });
  };

  return (
    <>
      <ProductView
        state={toViewState({
          isLoading: query.isLoading,
          data: query.data,
          error: query.error,
          refetch: query.refetch,
        })}
        onCheckout={query.data?.available === 0 && !hasProgress ? undefined : openProgress}
        hasProgress={hasProgress}
        returnNotice={progress.returnNotice}
      />
      {mode !== 'product' && (
        <CheckoutDialog
          productId={productId}
          mode={mode}
          onClose={backToProduct}
          onStatusRoute={() => void navigate(checkoutRoutes.status(productId), { replace: true })}
          onReturn={() => {
            void query.refetch();
            backToProduct();
          }}
        />
      )}
    </>
  );
};
