import { rmSync, readFileSync } from 'node:fs';

import typescript from '@rollup/plugin-typescript';
import { dts } from 'rollup-plugin-dts';

const extractDirectDependencies = (): string[] => {
  const { dependencies } = JSON.parse(
    readFileSync('package.json', 'utf8'),
  ) as Record<string, string>;

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  return Object.keys(dependencies!);
};

const dependencies = extractDirectDependencies();

const external = (id: string): boolean => {
  if (id.startsWith('node:')) {
    return true;
  }

  if (dependencies.includes(id)) {
    return true;
  }

  return false;
};

export default [
  {
    external,
    plugins: [
      {
        name: 'Pre/post cleanup',
        buildStart() {
          rmSync(new URL('dist/', import.meta.url), {
            recursive: true,
            force: true,
          });
        },
      },
      typescript(),
    ],
    input: {
      index: 'src/index.ts',
      'oauth2-mock-server': 'src/oauth2-mock-server.ts',
    },
    output: [
      {
        entryFileNames: '[name].js',
        chunkFileNames: 'shared/[name].js',
        dir: 'dist',
        format: 'es',
      },
    ],
  },
  {
    external,
    plugins: [
      dts({
        compilerOptions: {
          declaration: true,
          emitDeclarationOnly: true,
          removeComments: false,
        },
      }),
    ],
    input: 'src/index.ts',
    output: {
      file: 'dist/types/index.d.ts',
      format: 'es',
    },
  },
];
