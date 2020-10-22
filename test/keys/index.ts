import fs from 'fs';
import type { JWK } from 'node-jose';
import path from 'path';

export function get(filename: string): string {
  const filePath = path.join(__dirname, filename);
  const key = fs.readFileSync(filePath, 'utf8');

  return key;
}

export function getParsed(filename: string): JWK.Key {
  const key = get(filename)

  return JSON.parse(key) as JWK.Key;
}
