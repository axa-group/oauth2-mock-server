import { describe, it, expect } from 'vitest';

import type { CodeChallenge, PKCEAlgorithm } from '../src';
import {
  createPKCECodeChallenge,
  createPKCEVerifier,
  isValidPkceCodeVerifier,
  pkceVerifierMatchesChallenge,
} from '../src/lib/oauth2-service.pkce';

describe('isValidPkceCodeVerifier', () => {
  it('should accept a valid PKCE code_verifier', () => {
    const verifier128 =
      'PXa7p8YHHUAJGrcG2eW0x7FY_EBtRTlaUHnyz1jKWnNp0G-2HZt9KjA0UOp87DmuIqoV4Y_owVsM-QICvrSa5dWxOndVEhSsFMMgy68AYkw4PGHkGaN_aIRIHJ8mQ4EZ';
    const verifier42 = 'xyo94uhy3zKvgB0NJwLms86SwcjtWviEOpkBnGgaLlo';
    expect(isValidPkceCodeVerifier(verifier128)).toBe(true);
    expect(isValidPkceCodeVerifier(verifier42)).toBe(true);

    const verifierWith129chars = `${verifier128}a`;
    expect(isValidPkceCodeVerifier(verifierWith129chars)).toBe(false);
    expect(
      isValidPkceCodeVerifier(verifier42.slice(0, verifier42.length - 1))
    ).toBe(false);
  });

  it('should create a valid code_verifier', () => {
    expect(isValidPkceCodeVerifier(createPKCEVerifier())).toBe(true);
  });

  it('should create a valid code_challenge', async () => {
    const verifier = 'xyo94uhy3zKvgB0NJwLms86SwcjtWviEOpkBnGgaLlo';
    const expectedChallenge = 'b7elB7ZyxIXgFyvBznKvxl7wOB-H17Pz0a3B62NIMFI';
    const generatedCodeChallenge = await createPKCECodeChallenge(verifier, 'S256');
    expect(generatedCodeChallenge).toBe(expectedChallenge);
    const expectedCodeLength = 43;
    expect(
      await createPKCECodeChallenge(createPKCEVerifier(), 'S256')
    ).toHaveLength(expectedCodeLength);
  });

  it('should match code_verifier and code_challenge', async () => {
    const verifier = createPKCEVerifier();
    const codeChallengeMethod = 'S256';
    const challenge: CodeChallenge = {
      challenge: await createPKCECodeChallenge(verifier, codeChallengeMethod),
      method: codeChallengeMethod,
    };
    expect(await pkceVerifierMatchesChallenge(verifier, challenge)).toBe(true);
  });

  it('should throw on an unsupported method', async () => {
    const verifier = createPKCEVerifier();
    await expect(
      createPKCECodeChallenge(verifier, 'BAD-METHOD' as PKCEAlgorithm)
    ).rejects.toThrow('Unsupported PKCE method ("BAD-METHOD")');
  });
});
