import js from '@eslint/js'
import importPlugin from 'eslint-plugin-import'
import eslintN from 'eslint-plugin-n'
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
  // eslint-plugin-n 18 registers the "n" plugin inside its own flat configs, and
  // neostandard already registers it - spreading both makes eslint throw
  // "Cannot redefine plugin \"n\"". Its languageOptions and rules are taken
  // without the duplicate plugin registration.
  {
    languageOptions: eslintN.configs['flat/recommended'].languageOptions,
    rules: eslintN.configs['flat/recommended'].rules
  },
  promisePlugin.configs['flat/recommended'],
  {
    rules: {
      'n/no-unpublished-require': 'off',
    }
  }
]
