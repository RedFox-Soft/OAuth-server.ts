/*
 * The owner the root issuer's keys are stored under, in the same area as every bucket's keys. No bucket
 * id can take it — bucket ids are nanoids, which never contain `#` — so no bucket's deletion reaches it
 * and no bucket's lookup finds it. Import-free, so the test preload and the provisioning scripts can
 * name it without reaching the key modules.
 */
export const ROOT_KEY_OWNER = '#root';
