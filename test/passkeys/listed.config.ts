import { ApplicationConfig as listOn } from '../attacker_list/attacker_list.config.ts';
import { ApplicationConfig as passkeys, clients } from './passkeys.config.ts';

/*
 * The passkey projects of passkeys.config.ts with FoxTrust's attacker list on, as test/attacker_list/ runs it: a case
 * about a passkey sign-in from an address the list refuses passwords from.
 */
export const ApplicationConfig = { ...passkeys, ...listOn };

export { clients };
