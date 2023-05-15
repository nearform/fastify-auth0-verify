module.exports = {
  extends: ['eslint:recommended', 'plugin:prettier/recommended'],
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
