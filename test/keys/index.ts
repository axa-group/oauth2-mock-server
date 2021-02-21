import fs from 'fs';
import { JWK } from 'jose/types';
import path from 'path';

export function get(filename: string): string {
  const filePath = path.join(__dirname, filename);
  const key = fs.readFileSync(filePath, 'utf8');

  return key;
}

export function getParsed(filename: string): JWK {
  const key = get(filename);

  return JSON.parse(key) as JWK;
}
