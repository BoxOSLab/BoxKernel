// Starlight does not rewrite Markdown links. Pages in this site are flat
// files under src/content/docs/, published as /<slug>/ (index.md at the root).

function publishedHref(href, fromFile) {
  if (!href || href.startsWith('#') || href.startsWith('/') || href.startsWith('?')) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(href)) return null;

  const split = href.search(/[?#]/);
  const path = split === -1 ? href : href.slice(0, split);
  const suffix = split === -1 ? '' : href.slice(split);
  if (!path.endsWith('.md') || path.includes('..')) return null;

  const slug = path.replace(/^\.\//, '').slice(0, -'.md'.length);
  if (slug.includes('/')) return null;

  const fromName = fromFile ? decodeURIComponent(fromFile.pathname.split('/').pop() ?? '') : '';
  const fromIndex = fromName === 'index.md';
  let target;
  if (slug === 'index') target = fromIndex ? './' : '../';
  else if (fromIndex) target = `${slug}/`;
  else target = `../${slug}/`;
  return target + suffix;
}

/** Rewrite same-directory `page.md` links to the published paths. */
export function docLinks() {
  return {
    name: 'boxkernel-doc-links',
    link(node, ctx) {
      const next = publishedHref(node.url, ctx.fileURL);
      if (next) ctx.setProperty(node, 'url', next);
    },
    definition(node, ctx) {
      const next = publishedHref(node.url, ctx.fileURL);
      if (next) ctx.setProperty(node, 'url', next);
    },
  };
}
