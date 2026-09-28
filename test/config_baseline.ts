import { ApplicationConfig } from '../lib/configs/application.js';
import { ClientDefaults } from '../lib/configs/clientBase.js';

/*
 * The settings every `bootstrap` restores: the shipped defaults, as the process holds them before any
 * spec has run.
 *
 * Taken here, and loaded by test/preload.ts before the first spec file, because the moment it is taken
 * is the whole of its correctness. It used to be taken when test_helper was first imported — which is
 * whenever the first spec that imports it runs. A spec that does not import it (test/admin/
 * sentry_settings.spec.ts builds its own app) and saves a setting through the live settings route,
 * which applies it to the running process, ran first in the walk order: the snapshot then held its
 * value, and every later bootstrap faithfully "restored" `dpop.requireNonce: true`.
 *
 * Deep copies, and each bootstrap re-applies a fresh deep copy of them. A shallow snapshot shares every
 * nested value (`discovery`, `claims`, `scopes`, `clientAuthMethods`, ...) with the live config, so one
 * spec mutating a nested object in place would poison the baseline itself.
 */
export const applicationDefaultSettings = structuredClone(ApplicationConfig);
export const clientDefaultSettings = structuredClone(ClientDefaults);
