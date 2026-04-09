// Known popular GitHub repos that packages commonly starjack
const POPULAR_REPOS = new Set([
  'facebook/react', 'vuejs/vue', 'angular/angular', 'sveltejs/svelte',
  'vercel/next.js', 'expressjs/express', 'lodash/lodash', 'axios/axios',
  'webpack/webpack', 'eslint/eslint', 'prettier/prettier', 'jestjs/jest',
  'nodejs/node', 'microsoft/typescript', 'vitejs/vite', 'evanw/esbuild',
  'rollup/rollup', 'tailwindlabs/tailwindcss', 'prisma/prisma',
  'fastify/fastify', 'koajs/koa', 'socketio/socket.io', 'graphql/graphql-js',
  'winstonjs/winston', 'pinojs/pino', 'chalk/chalk', 'yargs/yargs',
]);

export function checkStarjacking(packageName, meta) {
  if (!meta?.repository) return null;

  const repoUrl = typeof meta.repository === 'string'
    ? meta.repository
    : meta.repository.url || '';

  const parsed = parseGitHubRepo(repoUrl);
  if (!parsed) return null;

  const repoFullName = `${parsed.owner}/${parsed.repo}`;

  // Only flag if the repo is in our popular list
  if (!POPULAR_REPOS.has(repoFullName)) return null;

  // Check if the package name plausibly belongs to this repo
  const bare = packageName.startsWith('@')
    ? packageName.split('/').pop()
    : packageName;

  // The package name should be related to the repo name
  const repoName = parsed.repo.toLowerCase().replace(/[.-]/g, '');
  const pkgName = bare.toLowerCase().replace(/[.-]/g, '');

  // Exact or substring match means it's likely legitimate
  // Require minimum length of 3 for substring matching to avoid short names
  // like "re" matching "react"
  if (repoName === pkgName) return null;
  if (pkgName.length >= 3 && (repoName.includes(pkgName) || pkgName.includes(repoName))) return null;

  // Scoped packages from the repo owner are likely legitimate
  if (packageName.startsWith('@')) {
    const scope = packageName.split('/')[0].slice(1);
    if (scope === parsed.owner.toLowerCase()) return null;
  }

  return {
    packageName,
    claimedRepo: repoFullName,
    repoUrl,
  };
}

function parseGitHubRepo(url) {
  // Handles:
  //   "https://github.com/owner/repo"
  //   "https://github.com/owner/repo.git"
  //   "git+https://github.com/owner/repo.git"
  //   "git://github.com/owner/repo.git"
  //   "github:owner/repo"
  //   "https://github.com/owner/repo.js"  (repos with dots like next.js)
  const m = url.match(/github\.com[/:]([^/]+)\/([^/#]+)/);
  if (m) {
    const repo = m[2].replace(/\.git$/, '').toLowerCase();
    return { owner: m[1].toLowerCase(), repo };
  }

  const shorthand = url.match(/^github:([^/]+)\/([^/#]+)/);
  if (shorthand) {
    const repo = shorthand[2].replace(/\.git$/, '').toLowerCase();
    return { owner: shorthand[1].toLowerCase(), repo };
  }

  return null;
}
