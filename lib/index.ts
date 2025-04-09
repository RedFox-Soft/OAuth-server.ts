/* eslint-disable import/first */
// eslint-disable-next-line import/order
import * as attention from './helpers/attention.ts';

const minimal = 'Jod';
const { lts: codename } = process.release || {};
if (!codename || codename.charCodeAt(0) < minimal.charCodeAt(0) || typeof Bun !== 'undefined' || typeof Deno !== 'undefined') {
  attention.warn('Unsupported runtime. Use Node.js v22.x LTS, or a later LTS release.');
}

import { Provider } from './provider.ts';
import * as errors from './helpers/errors.ts';
import * as interactionPolicy from './helpers/interaction_policy/index.ts';

export default Provider;
export { errors, interactionPolicy, Provider };
export { ExternalSigningKey } from './helpers/keystore.ts';
