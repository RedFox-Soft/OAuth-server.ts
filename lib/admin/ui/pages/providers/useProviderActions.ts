import { useCallback, useMemo } from 'react';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import {
	federationApi,
	isLastDoor,
	type PresentedProvider,
	type ProviderDetail
} from './providerTypes.js';

interface BucketDoors {
	passwordLogin?: boolean;
	federation?: { id: string; enabled: boolean }[];
}

const people = (n: number) => `${n} ${n === 1 ? 'person' : 'people'}`;

/*
 * Why a provider cannot be turned off or deleted right now, or null when it can (specs/084 US3). Said on the
 * control, before anyone presses it, from what the page already knows. Disabling a provider a directory is
 * bound to stays possible: it is how a compromised upstream is cut off, and the question says what it costs.
 */
export function providerBlocks(
	bucket: BucketDoors,
	provider: { id: string },
	bound: { displayName: string } | null
): { disable: string | null; remove: string | null } {
	const lastDoor = isLastDoor(bucket, provider.id)
		? 'This is the only way to sign in to this bucket: password sign-in is off and no other provider is enabled. Turn password sign-in on, or enable another provider, first.'
		: null;
	return {
		disable: lastDoor,
		remove:
			lastDoor ??
			(bound
				? `${bound.displayName} provisions this bucket through this provider. Delete that connection first.`
				: null)
	};
}

/*
 * Turning a provider on or off, and deleting it, asked at the weight each carries. The linked count is read
 * when the question opens rather than taken from a list, so it is the number at the moment of consent.
 */
export function useProviderActions(
	bucketId: string,
	consoleBucket: boolean
): {
	setEnabled: (
		provider: PresentedProvider,
		enabled: boolean
	) => Promise<boolean>;
	remove: (provider: PresentedProvider) => Promise<boolean>;
} {
	const feedback = useFeedback();
	const confirm = useConfirm();

	/*
	 * On the console's own bucket these acts can shut administrators out. The server refuses the one that
	 * would leave no super administrator a way in while passwords are off; the question says what remains.
	 */
	const consoleLines = useMemo(
		() =>
			consoleBucket
				? [
						'Administrators who sign in only through it will need their password, or another provider, to reach the console.'
					]
				: [],
		[consoleBucket]
	);

	const detailOf = useCallback(
		async (id: string): Promise<ProviderDetail | null> => {
			const result = await request<ProviderDetail>(
				'GET',
				federationApi(bucketId, id)
			);
			return result.ok ? result.data : null;
		},
		[bucketId]
	);

	const setEnabled = useCallback(
		async (provider: PresentedProvider, enabled: boolean) => {
			let proceed: boolean;
			if (enabled) {
				proceed = await confirm('provider.enable', {
					target: provider.displayName
				});
			} else {
				const detail = await detailOf(provider.id);
				proceed = await confirm('provider.disable', {
					target: provider.displayName,
					consequences: [
						`People who sign in only with ${provider.displayName} can't sign in until you enable it again.`,
						detail
							? `${people(detail.linkedUsers)} linked to it keep their accounts and links.`
							: 'Accounts and their links to it are kept.',
						...(detail?.boundConnection
							? [
									`${detail.boundConnection.displayName} provisions this bucket through it: the people it manages sign in with ${provider.displayName}, and can't while it is off.`
								]
							: []),
						...consoleLines
					]
				});
			}
			if (!proceed) return false;
			const result = await request(
				'PATCH',
				federationApi(bucketId, provider.id),
				{
					enabled
				}
			);
			if (!result.ok) {
				feedback.failed(result);
				return false;
			}
			feedback.done(
				`Identity provider ${provider.displayName} ${enabled ? 'enabled' : 'disabled'}.`
			);
			return true;
		},
		[bucketId, confirm, detailOf, feedback, consoleLines]
	);

	const remove = useCallback(
		async (provider: PresentedProvider) => {
			const detail = await detailOf(provider.id);
			const proceed = await confirm('provider.delete', {
				target: provider.displayName,
				consequences: [
					`${provider.displayName} and every person's link to it are removed. Those people keep their accounts and can sign in another way.`,
					...(detail
						? [`${people(detail.linkedUsers)} are linked to it now.`]
						: []),
					'Connecting it again later does not restore the links.',
					...consoleLines
				]
			});
			if (!proceed) return false;
			const result = await request(
				'DELETE',
				federationApi(bucketId, provider.id)
			);
			if (!result.ok) {
				feedback.failed(result);
				return false;
			}
			feedback.done(`Identity provider ${provider.displayName} deleted.`);
			return true;
		},
		[bucketId, confirm, detailOf, feedback, consoleLines]
	);

	return { setEnabled, remove };
}
