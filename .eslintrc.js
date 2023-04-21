module.exports = {
  extends: ['standard', 'plugin:prettier/recommended'],
  overrides: [
    {
      extends: ['standard', 'plugin:prettier/recommended'],
      files: ['test/**', 'test-integration/**'],
      plugins: ['jest'],
      env: {
        'jest/globals': true
      }
    }
  ]
}
