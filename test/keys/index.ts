import path from 'path';
import { readJsonFromFile } from '../../src/lib/helpers';

export function getParsed(filename: string): Record<string, unknown> {
  const filepath = path.join(__dirname, filename);
  return readJsonFromFile(filepath);
}
