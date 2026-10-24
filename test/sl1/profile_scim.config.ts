import * as profile from './profile.config.ts';
import {
	ApplicationConfig as scim,
	clients as scimClients
} from '../scim/scim.config.ts';

/* The IPSIE SL1 profile beside SCIM provisioning, test/scim's harness. */
export const jwks = profile.jwks;

export const ApplicationConfig = { ...scim, ...profile.ApplicationConfig };

export const clients = scimClients;

export default profile.default;
