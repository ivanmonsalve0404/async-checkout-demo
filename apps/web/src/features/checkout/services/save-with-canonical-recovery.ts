interface Versioned {
  readonly version: number;
}

const canRetrySave = (error: unknown): boolean => {
  if (error instanceof TypeError) {
    return true;
  }
  if (typeof error !== 'object' || error === null || !('status' in error)) {
    return false;
  }
  const status = error.status;
  return (
    status === 412 || typeof status === 'string' || (typeof status === 'number' && status >= 500)
  );
};

export const saveWithCanonicalRecovery = async <TCanonical extends Versioned>(
  initialVersion: number,
  save: (version: number) => Promise<Versioned>,
  refetch: () => PromiseLike<{ readonly data?: TCanonical | undefined }>,
  isApplied: (canonical: TCanonical) => boolean,
): Promise<number> => {
  let version = initialVersion;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      return (await save(version)).version;
    } catch (error) {
      const recovered = await refetch();
      if (recovered.data === undefined) {
        throw error;
      }
      if (isApplied(recovered.data)) {
        return recovered.data.version;
      }
      if (attempt === 1 || !canRetrySave(error)) {
        throw error;
      }
      version = recovered.data.version;
    }
  }
  throw new Error('UNREACHABLE_SAVE_RECOVERY');
};
