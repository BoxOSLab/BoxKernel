# BoxKernel documentation

The site is an [Astro Starlight](https://starlight.astro.build/) project.
Markdown pages live in `src/content/docs/`. The changelog page is generated
from the repository `CHANGELOG.md` at build time.

```console
$ npm ci
$ npm run dev      # http://localhost:4321/BoxKernel/
$ npm run build    # static site in dist/
```

GitHub Actions publishes `dist/` to GitHub Pages on pushes to `main`.
The site base path is `/BoxKernel`.
