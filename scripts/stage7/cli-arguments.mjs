const PNPM_SEPARATOR = '--';
const VALID_SEPARATOR_INDEXES = new Set([0, 1]);

const invalidContract = () => {
  const error = new Error('E7_CLI_ARGUMENT_NORMALIZATION_CONTRACT_INVALID');
  error.code = 'E7_CLI_ARGUMENT_NORMALIZATION_CONTRACT_INVALID';
  throw error;
};

export const normalizePnpmScriptArguments = (arguments_, { separatorIndex }) => {
  if (
    !Array.isArray(arguments_) ||
    !arguments_.every((argument) => typeof argument === 'string') ||
    !VALID_SEPARATOR_INDEXES.has(separatorIndex)
  ) {
    invalidContract();
  }

  const normalized = [...arguments_];
  if (normalized[separatorIndex] !== PNPM_SEPARATOR || separatorIndex === normalized.length - 1) {
    return normalized;
  }

  normalized.splice(separatorIndex, 1);
  return normalized;
};
