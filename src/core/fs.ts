import { promises as fs } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';

export async function exists(p: string): Promise<boolean> {
  try { await fs.access(p); return true; } catch { return false; }
}

export async function ensureDir(p: string) { await fs.mkdir(p, { recursive: true }); }

export async function readJson<T>(p: string, fallback: T): Promise<T> {
  try { return JSON.parse(await fs.readFile(p, 'utf8')) as T; } catch { return fallback; }
}

export async function writeJson(p: string, value: unknown) {
  await ensureDir(path.dirname(p));
  await fs.writeFile(p, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

export async function readYaml<T>(p: string, fallback: T): Promise<T> {
  try { return YAML.parse(await fs.readFile(p, 'utf8')) as T; } catch { return fallback; }
}

export async function writeYaml(p: string, value: unknown) {
  await ensureDir(path.dirname(p));
  await fs.writeFile(p, YAML.stringify(value) + '\n', 'utf8');
}

export async function readText(p: string): Promise<string | null> {
  try { return await fs.readFile(p, 'utf8'); } catch { return null; }
}

export async function writeText(p: string, value: string) {
  await ensureDir(path.dirname(p));
  await fs.writeFile(p, value, 'utf8');
}

export async function listFiles(root: string, maxFiles = 5000): Promise<string[]> {
  const out: string[] = [];
  const ignored = new Set(['.git', 'node_modules', '.next', 'dist', 'build', 'coverage', '.security']);
  async function walk(dir: string) {
    if (out.length >= maxFiles) return;
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (out.length >= maxFiles || ignored.has(entry.name)) continue;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(abs);
      else out.push(abs);
    }
  }
  await walk(root);
  return out;
}
