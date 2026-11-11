/*
 * Network facts from FoxTrust's snapshot (specs/129). Fixed in the release, like the publication itself
 * (lib/consts/foxtrust_publication.ts). Pure: the console imports the categories and the attribution.
 */

/*
 * Far above today's 13.2 MB full file (after FoxTrust spec 040) and its hourly updates, and low enough that the old
 * and the new data side by side stay inside the 60 MB the spec allows (SC-004). A file past it is refused unread.
 */
export const NETWORK_FACTS_FULL_MAX_BYTES = 40 * 1024 * 1024;
export const NETWORK_FACTS_DELTA_MAX_BYTES = 20 * 1024 * 1024;

/* FoxTrust's own staleness limit: a missed daily full still leaves the hourly updates. */
export const NETWORK_FACTS_STALE_SECONDS = 26 * 60 * 60;

/* FoxTrust's /verify looks this often; a new hourly update is in use within 10 minutes (SC-002). */
export const NETWORK_FACTS_TICK_MS = 5 * 60 * 1000;
export const NETWORK_FACTS_MAX_OFFSET_MS = 60 * 1000;

/* The one database type this release reads; any other is "update FoxAuth", never a guess. */
export const NETWORK_FACTS_DATABASE_TYPE = 'FoxTrust-Customer-Verdict';

export const NETWORK_CATEGORIES = ['tor', 'vpn', 'hosting'] as const;
export type NetworkCategory = (typeof NETWORK_CATEGORIES)[number];

/*
 * FoxTrust's categories a condition can name. `cloud` is one choice with `hosting` because an operator keeping data
 * centres out means both; every other FoxTrust category (Private Relay, crawlers, reserved space, future ones) is
 * ignored, never refused on.
 */
export const FOXTRUST_CATEGORY_MAP: Readonly<
	Record<string, NetworkCategory | undefined>
> = {
	tor: 'tor',
	vpn: 'vpn',
	hosting: 'hosting',
	cloud: 'hosting'
};

export const MAX_COUNTRIES = 250;

/* Records whose projection is cached; FoxTrust's full file held 16,193 distinct records on 2026-11-11. */
export const NETWORK_FACTS_CACHE_ENTRIES = 65_536;

/* DB-IP Country Lite is CC BY 4.0: the attribution goes wherever a country from it is shown. */
export const DBIP_ATTRIBUTION = 'IP Geolocation by DB-IP';
export const DBIP_ATTRIBUTION_URL = 'https://db-ip.com';
