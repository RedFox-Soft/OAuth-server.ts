import * as crypto from 'node:crypto';

import { InvalidGrant } from './errors.ts';
import checkFormat from './pkce_format.ts';
import constantEquals from './constant_equals.ts';

export default function checkPKCE(verifier, challenge, method) {
  if (verifier) {
    checkFormat(verifier, 'code_verifier');
  }

  if (verifier || challenge) {
    try {
      let expected = verifier;
      if (!expected) throw new Error();

      if (method === 'S256') {
        expected = crypto.hash('sha256', expected, 'base64url');
      } else {
        throw new Error();
      }

      if (!constantEquals(challenge, expected)) {
        throw new Error();
      }
    } catch (err) {
      throw new InvalidGrant('PKCE verification failed');
    }
  }
}
