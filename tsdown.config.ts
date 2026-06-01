import type { UserConfig } from 'tsdown';

// eslint-disable-next-line func-style
const _default: (options: UserConfig) => UserConfig = () => {
  return {
    entry: {
      index: 'src/index.ts',
      'oauth2-mock-server': 'src/oauth2-mock-server.ts', // CLI binary entry
    },
    format: 'esm',
    platform: 'node',
    clean: true,
    deps: {
      skipNodeModulesBundle: true,
    },
  };
};

export default _default;
