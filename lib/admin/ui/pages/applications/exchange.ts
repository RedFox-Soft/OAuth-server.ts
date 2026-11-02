/*
 * Whether an application can obtain people's tokens at a connected service (specs/118), as far as the console can
 * tell from the application's own view. The server's eligibility check is the rule and refuses by name; this only
 * explains, ahead of the request, why an option is not offered.
 */

export const TOKEN_EXCHANGE_GRANT =
	'urn:ietf:params:oauth:grant-type:token-exchange';

export interface ExchangeCandidate {
	clientId: string;
	clientName?: string;
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	registeredDynamically?: boolean;
}

export function whyCannotExchange(
	application: ExchangeCandidate
): string | null {
	if (application.registeredDynamically) {
		return 'it registered itself, and nobody vouched for it';
	}
	if (application.tokenEndpointAuthMethod === 'none') {
		return 'it does not authenticate (public application)';
	}
	if (!application.grantTypes.includes(TOKEN_EXCHANGE_GRANT)) {
		return 'it does not have the token exchange grant';
	}
	return null;
}

export function applicationName(
	clientId: string,
	applications: readonly ExchangeCandidate[]
): string {
	const found = applications.find((item) => item.clientId === clientId);
	return found?.clientName || clientId;
}

/*
 * Select options for the project's applications, an ineligible one disabled with its reason. An id the list does not
 * know (an application read before it was deleted) is still shown, so a stored value never renders as a bare id.
 */
export function exchangeOptions(
	applications: readonly ExchangeCandidate[],
	selected: readonly string[] = []
) {
	const options = applications.map((application) => {
		const why = whyCannotExchange(application);
		const name = application.clientName
			? `${application.clientName} (${application.clientId})`
			: application.clientId;
		return {
			value: application.clientId,
			label: why ? `${name} — ${why}` : name,
			disabled: why !== null && !selected.includes(application.clientId)
		};
	});
	for (const clientId of selected) {
		if (!applications.some((item) => item.clientId === clientId)) {
			options.push({ value: clientId, label: clientId, disabled: false });
		}
	}
	return options;
}
