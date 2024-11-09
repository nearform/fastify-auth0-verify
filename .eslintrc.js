module.exports = {
  extends: ['standard', 'plugin:prettier/recommended'],
  overrides: [
    {
      extends: ['standard', 'plugin:prettier/recommended'],
      files: ['test/**']
    }
  ]
}
