import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'

export default defineConfig({
  site: 'https://runok.fohte.net',
  integrations: [
    starlight({
      title: 'runok',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/fohte/runok',
        },
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
          slug: 'troubleshooting',
        },
      ],
    }),
  ],
})
