import { useCallback } from 'react';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import {
	connectionsApi,
	people,
	type ConnectionView
} from './connectionShared.js';

/*
 * Why a connection cannot be deleted, or null. Refused by the server while it manages anyone, because people
 * must never be removed or released as a side effect of deleting configuration.
 */
export function deleteBlock(c: ConnectionView): string | null {
	const groups = c.managedGroups;
	if (c.managedUsers === 0 && groups === 0) return null;
	return `Manages ${people(c.managedUsers)} and ${people(groups, 'group')}. Disable it instead, or remove them through the directory first.`;
}

/* Turning a connection on or off, and deleting it, asked at the weight each carries (specs/084 US5). */
export function useConnectionActions(bucketId: string): {
	setEnabled: (c: ConnectionView, enabled: boolean) => Promise<boolean>;
	remove: (c: ConnectionView) => Promise<boolean>;
} {
	const feedback = useFeedback();
	const confirm = useConfirm();

	const setEnabled = useCallback(
		async (c: ConnectionView, enabled: boolean) => {
			const proceed = enabled
				? await confirm('connection.enable', { target: c.displayName })
				: await confirm('connection.disable', {
						target: c.displayName,
						consequences: [
							`The ${c.managedUsers} ${c.managedUsers === 1 ? 'person' : 'people'} it manages keep their access.`,
							"The directory can't create, change or remove anyone until you enable it again.",
							'Nobody is deactivated.'
						]
					});
			if (!proceed) return false;
			const result = await request('PATCH', connectionsApi(bucketId, c.id), {
				enabled
			});
			if (!result.ok) {
				feedback.failed(result);
				return false;
			}
			feedback.done(
				`Provisioning connection ${c.displayName} ${enabled ? 'enabled' : 'disabled'}.`
			);
			return true;
		},
		[bucketId, confirm, feedback]
	);

	const remove = useCallback(
		async (c: ConnectionView) => {
			const proceed = await confirm('connection.delete', {
				target: c.displayName,
				consequences: [
					'The directory can no longer provision this bucket, and every token it holds is revoked.',
					'Its identity provider stays on this bucket, still limited to existing accounts.'
				]
			});
			if (!proceed) return false;
			const result = await request('DELETE', connectionsApi(bucketId, c.id));
			if (!result.ok) {
				feedback.failed(result);
				return false;
			}
			feedback.done(`Provisioning connection ${c.displayName} deleted.`);
			return true;
		},
		[bucketId, confirm, feedback]
	);

	return { setEnabled, remove };
}
