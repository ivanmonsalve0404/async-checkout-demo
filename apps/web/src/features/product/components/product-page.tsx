import { useGetProductQuery, type ProductResponse } from '../api/product-api';
import { ProductView, type ProductViewState } from './product-view';

export interface ProductQueryState {
  readonly isLoading: boolean;
  readonly data: ProductResponse | undefined;
  readonly error: unknown;
  readonly refetch: () => unknown;
}

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

export const ProductPage = ({ productId }: Readonly<{ productId: string }>) => {
  const query = useGetProductQuery(productId);
  return (
    <ProductView
      state={toViewState({
        isLoading: query.isLoading,
        data: query.data,
        error: query.error,
        refetch: query.refetch,
      })}
    />
  );
};
