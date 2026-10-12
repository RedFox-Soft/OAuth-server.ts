import { useState } from 'react';
import { App, Button, Flex, Modal, Select, Typography } from 'antd';
import { ConfirmDestruction } from '../../ConfirmDestruction.js';
import { useConfirm } from '../../frame/confirm.js';
import { useFeedback } from '../../frame/feedback.js';
import { request } from '../../frame/request.js';
import { usersApi, type EndUser } from './endUser.js';

/* The server's cap on one bulk request (specs/089); the list stops selecting at it. */
export const BULK_LIMIT = 100;

type BulkAct = 'deactivate' | 'activate' | 'sign-out' | 'delete';

interface BulkResult {
	results: {
		id: string;
		outcome: 'changed' | 'skipped' | 'failed';
		reason?: string;
	}[];
}

const SKIP_WORDS: Record<string, string> = {
	provisioned: 'managed by a directory',
	already_active: 'already active',
	already_inactive: 'already deactivated',
	not_found: 'no longer in this bucket'
};

function people(n: number): string {
	return n === 1 ? '1 person' : `${String(n)} people`;
}

/*
 * Who the server will pass over, said before anyone confirms (FR-022). Read from the rows on screen, so it is a
 * forecast: the server decides again per person, and its answer is what the result reports.
 */
function forecastSkips(act: BulkAct, rows: EndUser[]): string[] {
	const managed = rows.filter((r) => r.provisionedBy).length;
	const lines: string[] = [];
	if (act !== 'sign-out' && managed > 0) {
		lines.push(
			`${people(managed)} ${managed === 1 ? 'is' : 'are'} managed by a directory and will be skipped.`
		);
	}
	const local = rows.filter((r) => !r.provisionedBy);
	if (act === 'deactivate') {
		const already = local.filter((r) => !r.active).length;
		if (already > 0) lines.push(`${people(already)} already deactivated.`);
	}
	if (act === 'activate') {
		const already = local.filter((r) => r.active).length;
		if (already > 0) lines.push(`${people(already)} already active.`);
		if (local.some((r) => r.lockedLocally)) {
			lines.push('A locked account stays locked: unlock it on its own page.');
		}
	}
	return lines;
}

/*
 * The selection bar of a bucket's Users list (specs/089 US5). Every act is the single act repeated by the server
 * for each person, each with its own audit entry; the bar only gathers the ids, asks once, and reports per person.
 */
export function BulkUsersBar({
	bucketId,
	selected,
	onDone,
	onClear
}: {
	bucketId: string;
	selected: EndUser[];
	onDone: () => void;
	onClear: () => void;
}) {
	const confirm = useConfirm();
	const feedback = useFeedback();
	const { notification } = App.useApp();
	const [busy, setBusy] = useState(false);
	const [deleting, setDeleting] = useState(false);
	const [grouping, setGrouping] = useState(false);
	const [groups, setGroups] = useState<
		{ id: string; displayName: string; provisionedBy?: string }[]
	>([]);
	const [groupId, setGroupId] = useState<string | undefined>(undefined);
	const groupsApi = `/admin/api/buckets/${encodeURIComponent(bucketId)}/groups`;
	const n = selected.length;

	function report(act: BulkAct, data: BulkResult) {
		const changed = data.results.filter((r) => r.outcome === 'changed').length;
		const skipped = data.results.filter((r) => r.outcome === 'skipped');
		const failed = data.results.filter((r) => r.outcome === 'failed');
		const verb = {
			deactivate: 'Deactivated',
			activate: 'Activated',
			'sign-out': 'Signed out',
			delete: 'Deleted'
		}[act];
		const reasons = [
			...new Set(skipped.map((r) => SKIP_WORDS[r.reason ?? ''] ?? r.reason))
		].join(', ');
		const emailOf = (id: string) =>
			selected.find((u) => u._id === id)?.email ?? id;
		const parts = [
			`${verb} ${String(changed)}.`,
			...(skipped.length
				? [`Skipped ${String(skipped.length)} (${reasons}).`]
				: []),
			...(failed.length
				? [
						`Failed ${String(failed.length)}: ${failed.map((r) => emailOf(r.id)).join(', ')}.`
					]
				: [])
		];
		if (failed.length) {
			notification.error({
				title: 'Some changes did not go through',
				description: parts.join(' '),
				duration: 0
			});
		} else {
			notification.success({ title: parts.join(' ') });
		}
	}

	async function run(act: BulkAct) {
		setBusy(true);
		try {
			const result = await request<BulkResult>(
				'POST',
				`${usersApi(bucketId)}/bulk/${act}`,
				{ userIds: selected.map((u) => u._id) }
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			report(act, result.data);
			onDone();
		} finally {
			setBusy(false);
		}
	}

	async function ask(act: Exclude<BulkAct, 'delete'>) {
		const effect = {
			deactivate:
				"They are signed out everywhere and can't sign in until activated.",
			activate: 'They can sign in again.',
			'sign-out':
				'Every session and token they hold ends; they sign in again next time.'
		}[act];
		const question = {
			target: people(n),
			consequences: [effect, ...forecastSkips(act, selected)]
		};
		// Each id spelled out: the console's frame test finds the questions a screen asks by their literal ids.
		const agreed =
			act === 'deactivate'
				? await confirm('users.bulk.deactivate', question)
				: act === 'activate'
					? await confirm('users.bulk.activate', question)
					: await confirm('users.bulk.signout', question);
		if (agreed) await run(act);
	}

	async function openGroups() {
		const result = await request<{
			groups: { id: string; displayName: string; provisionedBy?: string }[];
		}>('GET', groupsApi);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		setGroups(result.data.groups.filter((g) => !g.provisionedBy));
		setGroupId(undefined);
		setGrouping(true);
	}

	async function addToGroup() {
		const group = groups.find((g) => g.id === groupId);
		if (!group) return;
		setBusy(true);
		try {
			const result = await request(
				'POST',
				`${groupsApi}/${encodeURIComponent(group.id)}/members`,
				{ userIds: selected.map((u) => u._id) }
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(`${people(n)} added to ${group.displayName}.`);
			setGrouping(false);
			onDone();
		} finally {
			setBusy(false);
		}
	}

	return (
		<>
			<Flex
				align="center"
				gap={8}
				wrap
				style={{ marginBottom: 12 }}
				role="toolbar"
				aria-label="Selected users"
			>
				<Typography.Text strong>{n} selected</Typography.Text>
				<Button
					disabled={busy}
					onClick={() => void ask('deactivate')}
				>
					Deactivate
				</Button>
				<Button
					disabled={busy}
					onClick={() => void ask('activate')}
				>
					Activate
				</Button>
				<Button
					disabled={busy}
					onClick={() => void ask('sign-out')}
				>
					Sign out everywhere
				</Button>
				<Button
					disabled={busy}
					onClick={() => void openGroups()}
				>
					Add to group…
				</Button>
				<Button
					danger
					disabled={busy}
					onClick={() => setDeleting(true)}
				>
					Delete…
				</Button>
				<Button
					type="link"
					onClick={onClear}
				>
					Clear
				</Button>
			</Flex>
			{deleting && (
				<ConfirmDestruction
					open
					title={`Delete ${people(n)}?`}
					okText="Delete"
					consequences={[
						'Their accounts, sessions, tokens and links to identity providers are destroyed. This cannot be undone.',
						...forecastSkips('delete', selected)
					]}
					busy={busy}
					onCancel={() => setDeleting(false)}
					onConfirm={() => {
						setDeleting(false);
						void run('delete');
					}}
				/>
			)}
			<Modal
				title={`Add ${people(n)} to a group`}
				open={grouping}
				onCancel={() => setGrouping(false)}
				onOk={() => void addToGroup()}
				okText="Add to group"
				okButtonProps={{ disabled: !groupId }}
				confirmLoading={busy}
				destroyOnHidden
			>
				<Select
					style={{ width: '100%' }}
					placeholder={
						groups.length > 0
							? 'Choose a group'
							: 'No group administrators keep in this bucket'
					}
					disabled={groups.length === 0}
					value={groupId}
					onChange={setGroupId}
					options={groups.map((g) => ({ value: g.id, label: g.displayName }))}
				/>
			</Modal>
		</>
	);
}
