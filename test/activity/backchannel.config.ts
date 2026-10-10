/*
 * The backchannel arrangement test/acr settled on, unchanged: whether a back-channel approval counts as
 * activity is a question about the same flow, and CIBA ships off, so it needs this configuration.
 */
export {
	addons,
	ApplicationConfig,
	clients,
	default
} from '../acr/backchannel.config.ts';
