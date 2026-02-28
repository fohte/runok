import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'
import starlightLlmsTxt from 'starlight-llms-txt'

export default defineConfig({
  site: 'https://runok.fohte.net',
  integrations: [
    starlight({
      title: 'runok',
      customCss: ['./src/styles/custom.css'],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/fohte/runok',
        },
      ],
      plugins: [
        starlightLlmsTxt({
          projectName: 'runok',
          description:
            'A command allowlisting tool for AI coding agents and human developers.',
          promote: ['index*', 'getting-started*'],
        }),
      ],
      sidebar: [
        {
          label: 'Getting Started',
          autogenerate: { directory: 'getting-started' },
        },
        {
          label: 'Configuration',
          autogenerate: { directory: 'configuration' },
        },
        {
          label: 'Pattern Syntax',
          autogenerate: { directory: 'pattern-syntax' },
        },
        {
          label: 'Rule Evaluation',
          autogenerate: { directory: 'rule-evaluation' },
        },
        {
          label: 'Sandbox',
          autogenerate: { directory: 'sandbox' },
        },
        {
          label: 'CLI Reference',
          autogenerate: { directory: 'cli' },
        },
        {
          label: 'Extensions',
          autogenerate: { directory: 'extensions' },
        },
        {
          label: 'Architecture',
          autogenerate: { directory: 'architecture' },
        },
        {
          label: 'Recipes',
          autogenerate: { directory: 'recipes' },
        },
        {
          label: 'Troubleshooting',
          autogenerate: { directory: 'troubleshooting' },
        },
      ],
    }),
  ],
})
