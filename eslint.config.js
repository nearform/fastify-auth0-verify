import js from '@eslint/js'
import importPlugin from 'eslint-plugin-import'
import eslintPrettier from 'eslint-plugin-prettier/recommended'
import promisePlugin from 'eslint-plugin-promise'
import neostandard from 'neostandard'

export default [
  ...neostandard({
    ignores: neostandard.resolveIgnoresFromGitignore()
  }),
  js.configs.recommended,
  eslintPrettier,
  importPlugin.flatConfigs.recommended,
  promisePlugin.configs['flat/recommended'],
  {
    rules: {
      'n/no-unpublished-require': 'off',
    }
  }
]
