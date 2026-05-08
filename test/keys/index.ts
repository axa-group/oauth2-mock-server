import path from 'node:path';

import { readJsonFromFile } from '../../src/cli';

export const getParsedKey = (filename: string): Record<string, unknown> => {
  const filepath = path.join(__dirname, filename);
  return readJsonFromFile(filepath);
};
