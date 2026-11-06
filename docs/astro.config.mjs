// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { satteri } from '@astrojs/markdown-satteri';
import { docLinks } from './plugins/doc-links.mjs';

// GitHub Pages project site: https://boxoslab.github.io/BoxKernel/
export default defineConfig({
  site: 'https://boxoslab.github.io',
  base: '/BoxKernel',
  markdown: {
    processor: satteri({ mdastPlugins: [docLinks()] }),
  },
  integrations: [
    starlight({
      title: 'BoxKernel',
      description:
        'User-space chroot, bind mounts and binfmt_misc. A clean-room Rust rewrite of PRoot.',
      logo: { src: './src/assets/mark.svg' },
      favicon: '/favicon.svg',
      lastUpdated: true,
      editLink: {
        baseUrl: 'https://github.com/BoxOSLab/BoxKernel/edit/main/docs/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/BoxOSLab/BoxKernel',
        },
      ],
      customCss: [
        '@fontsource/literata/400.css',
        '@fontsource/literata/600.css',
        '@fontsource/literata/700.css',
        '@fontsource/dm-mono/400.css',
        '@fontsource/dm-mono/500.css',
        './src/styles/custom.css',
      ],
      sidebar: [
        { label: 'Introduction', slug: 'index' },
        {
          label: 'User guide',
          items: [
            { label: 'Installation', slug: 'installation' },
            { label: 'Usage and recipes', slug: 'usage' },
            { label: 'Command-line reference', slug: 'options' },
            { label: 'Mixed mode and QEMU', slug: 'mixed-mode' },
            { label: 'Security model', slug: 'security' },
          ],
        },
        {
          label: 'Internals',
          items: [
            { label: 'Architecture', slug: 'architecture' },
            { label: 'Extension framework', slug: 'extensions' },
          ],
        },
        {
          label: 'Contributing',
          items: [
            { label: 'Development guide', slug: 'development' },
            { label: 'Testing', slug: 'testing' },
            { label: 'Performance', slug: 'performance' },
            { label: 'Compatibility with C PRoot', slug: 'compatibility' },
          ],
        },
        { label: 'Changelog', slug: 'changelog' },
        { label: 'Manual page', slug: 'manpage' },
      ],
    }),
  ],
});
