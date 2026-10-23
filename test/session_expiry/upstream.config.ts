/*
 * The upstream back-channel logout arrangement, unchanged: federation on, and two relying parties signing
 * in through a stub provider — the only way a session learns where it came from.
 */
export {
	ApplicationConfig,
	clients,
	default
} from '../upstream_backchannel_logout/upstream_backchannel_logout.config.ts';
