module.exports = {
  extends: ['eslint:recommended', 'plugin:prettier/recommended'],
  env: {
    "node": true,
    "es2021": true
  },
  parserOptions: {
    "ecmaVersion": 2022,
    "sourceType": "module"
  },
  overrides: [
    {
      extends: ['eslint:recommended', 'plugin:prettier/recommended'],
      files: ['test/**'],
      plugins: ['jest'],
      env: {
        'jest/globals': true
      }
    }
  ]
}
