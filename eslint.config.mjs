import eslint from '@eslint/js';
import jsdoc from 'eslint-plugin-jsdoc';
import tseslint from 'typescript-eslint';
import prettierConfig from 'eslint-config-prettier';
import eslintPluginPrettierRecommendedConfig from 'eslint-plugin-prettier/recommended';
import importPlugin from 'eslint-plugin-import';
import vitest from '@vitest/eslint-plugin';

export default tseslint.config(
  eslint.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  prettierConfig,
  eslintPluginPrettierRecommendedConfig,
  importPlugin.flatConfigs.recommended,
  importPlugin.flatConfigs.typescript,
  jsdoc.configs['flat/recommended-typescript'],
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    ignores: ['node_modules/*', 'dist/*', 'coverage/*', '.vscode/*'],
  },
  {
    rules: {
      curly: 'warn',
      eqeqeq: 'warn',
      semi: 'warn',
      '@typescript-eslint/consistent-type-imports': 'warn',
      'jsdoc/require-jsdoc': [
        'warn',
        {
          publicOnly: true,
        },
      ],
      "import/order": [
        "error",
        {
          "groups": [
            "builtin",
            "external",
            "internal",
            "parent",
            "sibling",
            "index"
          ],
          "newlines-between": "always"
        }
      ],
    },
  },
  {
    files: ['test/**/*.test.ts'],
    plugins: {
      vitest,
    },
    rules: {
      ...vitest.configs.recommended.rules,
    },
    settings: {
      vitest: {
        typecheck: true,
      },
    },
    languageOptions: {
      globals: {
        ...vitest.environments.env.globals,
      },
    },
  },
  {
    files: ['test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      'jsdoc/require-jsdoc': 'off',
    },
  },
);
