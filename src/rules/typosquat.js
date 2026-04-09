// Top popular npm packages — reduced set for fast matching.
// In production this would be fetched/cached from npm's API.
const POPULAR_PACKAGES = [
  'express', 'react', 'lodash', 'axios', 'chalk', 'commander', 'debug',
  'dotenv', 'eslint', 'glob', 'inquirer', 'jest', 'jquery', 'minimist',
  'mkdirp', 'moment', 'mongoose', 'morgan', 'next', 'node-fetch',
  'nodemon', 'npm', 'passport', 'prettier', 'react-dom', 'react-router',
  'redis', 'request', 'rimraf', 'rxjs', 'semver', 'socket.io',
  'typescript', 'underscore', 'uuid', 'webpack', 'yargs', 'zod',
  'vue', 'angular', 'svelte', 'bluebird', 'async', 'colors', 'cheerio',
  'cors', 'crypto-js', 'dayjs', 'electron', 'ember', 'fastify',
  'firebase', 'graphql', 'gulp', 'handlebars', 'helmet', 'jsonwebtoken',
  'knex', 'koa', 'marked', 'mocha', 'mysql', 'pg', 'pino', 'puppeteer',
  'sequelize', 'sharp', 'sinon', 'superagent', 'tailwindcss', 'tar',
  'three', 'winston', 'ws', 'yaml', 'esbuild', 'vite', 'rollup',
  'turbo', 'prisma', 'drizzle-orm', 'hono', 'bun', 'deno',
];

// Popular scoped packages — checked with full scope
const POPULAR_SCOPED = [
  '@types/node', '@types/react', '@types/jest', '@types/express',
  '@babel/core', '@babel/preset-env', '@babel/cli', '@babel/parser',
  '@vue/cli', '@vue/compiler-sfc', '@vue/reactivity',
  '@angular/core', '@angular/cli', '@angular/common',
  '@eslint/js', '@eslint/eslintrc',
  '@testing-library/react', '@testing-library/jest-dom',
  '@emotion/react', '@emotion/styled',
  '@mui/material', '@mui/icons-material',
  '@prisma/client', '@trpc/server', '@trpc/client',
  '@tanstack/react-query', '@tanstack/react-table',
  '@anthropic-ai/sdk', '@openai/api',
];

export function checkTyposquat(name) {
  // Strip scope for comparison: "@evil/lodash" → "lodash"
  const bare = name.startsWith('@') ? name.split('/').pop() : name;

  // Check scoped packages against scoped popular list (full name comparison)
  if (name.startsWith('@')) {
    for (const popular of POPULAR_SCOPED) {
      if (name === popular) continue; // exact match is fine
      const dist = levenshtein(name, popular);
      if (dist > 0 && dist <= 2) {
        return { suspect: name, similarTo: popular, distance: dist };
      }
    }
  }

  for (const popular of POPULAR_PACKAGES) {
    if (bare === popular) continue; // exact match is fine
    // For very short names (<=2 chars like "ws", "pg"), only flag distance 1
    // with a minimum bare name length of 2 to avoid excessive false positives
    if (popular.length <= 2 && bare.length < 2) continue;
    const dist = levenshtein(bare, popular);
    const threshold = popular.length <= 4 ? 1 : 2;
    if (dist > 0 && dist <= threshold) {
      return { suspect: name, similarTo: popular, distance: dist };
    }
  }

  // Also check for common typosquat patterns
  for (const popular of POPULAR_PACKAGES) {
    if (bare === popular) continue;
    if (isDelimiterVariant(bare, popular)) {
      return { suspect: name, similarTo: popular, distance: 1 };
    }
  }

  return null;
}

function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      const cost = b[i - 1] === a[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }

  return matrix[b.length][a.length];
}

// Checks for delimiter variants: "lodash" vs "lod-ash", "lod_ash", "lod.ash"
function isDelimiterVariant(name, popular) {
  const normalize = (s) => s.replace(/[-_.]/g, '');
  return normalize(name) === normalize(popular) && name !== popular;
}
