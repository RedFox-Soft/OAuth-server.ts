// Test-only toggles for the resourceIndicators config hooks (useGrantedResource / defaultResource).
// The spec flips these per case instead of sending non-standard request parameters, so the strict
// /token schema stays unchanged. Both the config and the spec import this same module instance.
export const grantFlags = {
	useGranted: false,
	noDefault: false
};

export function resetGrantFlags() {
	grantFlags.useGranted = false;
	grantFlags.noDefault = false;
}
