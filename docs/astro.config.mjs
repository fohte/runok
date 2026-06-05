import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'
import starlightLinksValidator from 'starlight-links-validator'
import starlightLlmsTxt from 'starlight-llms-txt'

export default defineConfig({
  site: 'https://runok.fohte.net',
  integrations: [
    starlight({
      title: 'runok',
      favicon: '/favicon.svg',
      logo: {
        dark: './src/assets/logo-dark.svg',
        light: './src/assets/logo-light.svg',
        alt: 'runok',
        replacesTitle: true,
      },
      customCss: ['./src/styles/custom.css'],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/fohte/runok',
        },
      ],
      plugins: [
        starlightLinksValidator(),
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
          items: [{ autogenerate: { directory: 'getting-started' } }],
        },
        {
          label: 'Configuration',
          items: [{ autogenerate: { directory: 'configuration' } }],
        },
        {
          label: 'Pattern Syntax',
          items: [{ autogenerate: { directory: 'pattern-syntax' } }],
        },
        {
          label: 'Rule Evaluation',
          items: [{ autogenerate: { directory: 'rule-evaluation' } }],
        },
        {
          label: 'Sandbox',
          items: [{ autogenerate: { directory: 'sandbox' } }],
        },
        {
          label: 'CLI Reference',
          items: [{ autogenerate: { directory: 'cli' } }],
        },
        {
          label: 'Extensions',
          items: [{ autogenerate: { directory: 'extensions' } }],
        },
        {
          label: 'Architecture',
          items: [{ autogenerate: { directory: 'architecture' } }],
        },
        {
          label: 'Troubleshooting',
          items: [{ autogenerate: { directory: 'troubleshooting' } }],
        },
        {
          label: 'Releases',
          items: [{ autogenerate: { directory: 'releases' } }],
        },
      ],
    }),
  ],
})
