import path from 'node:path';
import { exists, readText, listFiles } from './fs.js';
import type { ProjectContext } from './types.js';

const hasAny = async (root: string, files: string[]) => {
  const found: string[] = [];
  for (const f of files) if (await exists(path.join(root, f))) found.push(f);
  return found;
};

export async function discoverProject(root: string): Promise<ProjectContext> {
  const pkgRaw = await readText(path.join(root, 'package.json'));
  let pkg: any = {};
  if (pkgRaw) { try { pkg = JSON.parse(pkgRaw); } catch {} }
  const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) } as Record<string, string>;
  const depNames = Object.keys(deps);

  const framework: string[] = [];
  if (depNames.includes('next')) framework.push('nextjs');
  if (depNames.includes('react')) framework.push('react');
  if (depNames.includes('vue') || depNames.includes('nuxt')) framework.push('vue/nuxt');
  if (depNames.includes('express')) framework.push('express');
  if (depNames.includes('fastify')) framework.push('fastify');
  if (depNames.includes('@nestjs/core')) framework.push('nestjs');
  if (depNames.includes('svelte') || depNames.includes('@sveltejs/kit')) framework.push('svelte');

  const backend: string[] = [];
  for (const d of ['express', 'fastify', '@nestjs/core', 'hono', 'next', 'stripe', 'paypal']) {
    if (depNames.includes(d)) backend.push(d);
  }

  const databases: string[] = [];
  const dbMapping: Record<string, string> = {
    prisma: 'postgres-or-multi-db-via-prisma',
    drizzle: 'drizzle',
    pg: 'postgresql',
    mysql: 'mysql',
    mysql2: 'mysql',
    mongoose: 'mongodb',
    mongodb: 'mongodb',
    redis: 'redis',
    ioredis: 'redis',
    '@supabase/supabase-js': 'supabase',
    sqlite3: 'sqlite',
    sqlite: 'sqlite',
    'better-sqlite3': 'sqlite'
  };
  for (const [needle, label] of Object.entries(dbMapping)) {
    if (depNames.includes(needle) && !databases.includes(label)) databases.push(label);
  }

  const aiProviders: string[] = [];
  const aiFrameworks: string[] = [];
  const aiMapping: Record<string, string> = {
    openai: 'openai',
    '@anthropic-ai/sdk': 'anthropic',
    '@google/generative-ai': 'gemini',
    '@ai-sdk/openai': 'openai',
    '@ai-sdk/anthropic': 'anthropic',
    '@ai-sdk/google': 'gemini'
  };
  for (const [needle, label] of Object.entries(aiMapping)) {
    if (depNames.includes(needle) && !aiProviders.includes(label)) aiProviders.push(label);
  }

  const aiFrameworkMapping: Record<string, string> = {
    langchain: 'langchain',
    '@langchain/core': 'langchain',
    ai: 'vercel-ai-sdk',
    llamaindex: 'llamaindex'
  };
  for (const [needle, label] of Object.entries(aiFrameworkMapping)) {
    if (depNames.includes(needle) && !aiFrameworks.includes(label)) aiFrameworks.push(label);
  }

  const authProviders: string[] = [];
  const authMapping: Record<string, string> = {
    '@clerk/nextjs': 'clerk',
    'next-auth': 'next-auth',
    '@auth/core': 'auth.js',
    'passport': 'passport',
    'firebase': 'firebase-auth',
    '@supabase/supabase-js': 'supabase-auth',
    'google-auth-library': 'google-oauth',
    '@react-oauth/google': 'google-oauth',
    'passport-google-oauth20': 'google-oauth',
    'bcrypt': 'custom-password-hashing',
    'bcryptjs': 'custom-password-hashing',
    'argon2': 'custom-password-hashing',
    'jsonwebtoken': 'custom-jwt'
  };
  for (const [needle, label] of Object.entries(authMapping)) {
    if (depNames.includes(needle) && !authProviders.includes(label)) authProviders.push(label);
  }

  // Scan files for additional stacks or signals (Google OAuth, custom auth, etc.)
  let files: string[] = [];
  try {
    files = await listFiles(root);
  } catch {}

  const detectedFiles = await hasAny(root, [
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'terraform', 'vercel.json', 'next.config.js', 'next.config.mjs', '.env.example', 'prisma/schema.prisma'
  ]);

  // If we find files that match auth patterns, add Google OAuth / Custom Auth signals
  let hasGoogleOAuthCode = false;
  let hasCustomAuthCode = false;
  let hasPaymentCode = false;
  let hasWebhookCode = false;

  const entryPoints: Array<{ kind: string; path: string }> = [];
  const sensitiveSignals: string[] = [];

  for (const file of files) {
    const relPath = path.relative(root, file);
    
    // Check files under api or routes
    if (/\b(api|routes|controllers|handlers)\b/i.test(relPath)) {
      if (/\.(ts|tsx|js|jsx)$/.test(file)) {
        entryPoints.push({ kind: 'api_endpoint', path: relPath });
      }
    }

    if (/\.(ts|tsx|js|jsx|json)$/.test(file)) {
      try {
        const text = await readText(file);
        if (text) {
          if (text.includes('accounts.google.com') || text.includes('GoogleAuthProvider') || text.includes('GoogleLogin') || text.includes('passport-google')) {
            hasGoogleOAuthCode = true;
          }
          if (text.includes('bcrypt') || text.includes('argon2') || (text.includes('jwt.sign') && !text.includes('@clerk/')) || text.includes('session.user')) {
            hasCustomAuthCode = true;
          }
          if (text.includes('stripe') || text.includes('payment') || text.includes('refund') || text.includes('paypal')) {
            hasPaymentCode = true;
          }
          if (text.includes('webhook') || text.includes('/webhook') || text.includes('req.headers[\'stripe-signature\']')) {
            hasWebhookCode = true;
          }
        }
      } catch {}
    }
  }

  if (hasGoogleOAuthCode && !authProviders.includes('google-oauth')) {
    authProviders.push('google-oauth');
  }
  if (hasCustomAuthCode && !authProviders.includes('custom')) {
    authProviders.push('custom');
  }
  if (hasPaymentCode) {
    sensitiveSignals.push('payments');
  }
  if (hasWebhookCode) {
    sensitiveSignals.push('webhooks');
  }
  if (files.some(f => f.endsWith('.tf'))) {
    detectedFiles.push('terraform');
  }
  if (await exists(path.join(root, '.github/workflows'))) {
    detectedFiles.push('.github/workflows');
  }

  const name = typeof pkg.name === 'string' ? pkg.name : path.basename(root);
  return {
    name,
    root,
    type: framework.includes('nextjs') || framework.includes('react') ? 'web_application' : backend.length ? 'api_or_backend' : 'software_project',
    stack: { frontend: framework, backend, database: databases, detectedFiles },
    authentication: { detected: authProviders.length > 0, providers: authProviders },
    ai: { detected: aiProviders.length > 0 || aiFrameworks.length > 0, providers: aiProviders, frameworks: aiFrameworks },
    database: { detected: databases.length > 0, systems: databases },
    entryPoints,
    sensitiveSignals,
    discoveredAt: new Date().toISOString()
  };
}
