const { existsSync } = require('fs')
const { join } = require('path')

// Plugin file exists only in public repos (controlled by copier is_public parameter)
const pluginPath = join(__dirname, 'commitlint-plugin-no-external-refs.cjs')
// eslint-disable-next-line @typescript-eslint/no-require-imports
const noExternalGitHubRefsPlugin = existsSync(pluginPath)
  ? require(pluginPath)
  : null

const config = {
  rules: {
    'body-leading-blank': [2, 'always'],
    'footer-leading-blank': [2, 'always'],
    'subject-full-stop': [2, 'never', '.'],
    ...(noExternalGitHubRefsPlugin && {
      'no-external-github-refs': [2, 'always'],
    }),
  },
  plugins: noExternalGitHubRefsPlugin ? [noExternalGitHubRefsPlugin] : [],
}

module.exports = config
