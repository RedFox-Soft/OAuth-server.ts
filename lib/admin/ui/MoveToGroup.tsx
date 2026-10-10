import { useEffect, useState } from 'react';
import { Alert, Modal, Select, Space, Typography, message } from 'antd';
import type { ScopeOption } from './pages/ScopeSwitcher.js';
import { groupLabel } from '../groups/label.js';
import { moveDestinations } from './ownership/model.js';

interface GroupRef {
	id: string;
	kind: ScopeOption['kind'] | null;
	name: string | null;
}

interface Preview {
	from: GroupRef;
	to: GroupRef;
	projects?: Array<{ id: string; name: string }>;
	consequence: string;
}

/*
 * Moving a bucket, with the projects using it, or a project with no bucket, to another administrator
 * group (specs/075).
 *
 * Two steps, because the server's preview is the only place the full list of what moves exists: the
 * first request names the destination and is answered with what would move; the second repeats it with
 * `confirm`. No typed word, unlike a deletion — nothing is destroyed, and a move can be moved back by
 * anyone who owns the group it lands in.
 */
export function MoveToGroup({
	kind,
	id,
	name,
	sourceGroupId,
	onClose,
	onMoved
}: {
	kind: 'bucket' | 'project';
	id: string;
	name: string;
	sourceGroupId: string;
	onClose: () => void;
	onMoved: () => void;
}) {
	const [scope, setScope] = useState<ScopeOption[] | null>(null);
	const [groupId, setGroupId] = useState<string | null>(null);
	const [preview, setPreview] = useState<Preview | null>(null);
	const [busy, setBusy] = useState(false);

	useEffect(() => {
		void (async () => {
			const res = await fetch('/admin/api/scope');
			if (!res.ok) return;
			const view = (await res.json()) as { available: ScopeOption[] };
			setScope(view.available);
		})();
	}, []);
	const options = scope && moveDestinations(scope, sourceGroupId);

	/*
	 * The preview's groups carry what is stored, never a label: a personal group reads "Personal" to its
	 * own administrator and names its owner to anyone else, and only the console knows who is looking. The
	 * scope list says whether a personal group is the viewer's own — the whole list, since the group a
	 * container leaves is never among the destinations — and one absent from it is somebody else's.
	 */
	function labelOf(group: GroupRef): string {
		const listed = scope?.find((o) => o.id === group.id);
		if (listed) return groupLabel(listed);
		if (group.kind === null || group.name === null) return group.id;
		return groupLabel({ kind: group.kind, name: group.name, own: false });
	}

	async function send(confirm: boolean) {
		if (!groupId) return;
		setBusy(true);
		try {
			const res = await fetch(
				`/admin/api/${kind === 'bucket' ? 'buckets' : 'projects'}/${encodeURIComponent(id)}/owner`,
				{
					method: 'PUT',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify(confirm ? { groupId, confirm } : { groupId })
				}
			);
			const body = (await res.json().catch(() => null)) as
				(Preview & { confirmationRequired?: boolean; message?: string }) | null;
			if (res.status === 409 && body?.confirmationRequired) {
				setPreview(body);
				return;
			}
			if (!res.ok) {
				void message.error(body?.message ?? 'The move was refused.');
				return;
			}
			void message.success(`${name} moved.`);
			onMoved();
		} finally {
			setBusy(false);
		}
	}

	return (
		<Modal
			open
			title={`Move ${name} to another group`}
			okText={preview ? 'Move' : 'Next'}
			okButtonProps={{ disabled: !groupId }}
			confirmLoading={busy}
			onOk={() => void send(preview !== null)}
			onCancel={onClose}
			destroyOnHidden
		>
			<Space
				orientation="vertical"
				style={{ width: '100%' }}
			>
				<Select
					placeholder="Destination group"
					loading={options === null}
					value={groupId ?? undefined}
					onChange={(value: string) => {
						setGroupId(value);
						setPreview(null);
					}}
					style={{ width: '100%' }}
					options={(options ?? []).map((g) => ({
						value: g.id,
						label: groupLabel(g)
					}))}
					notFoundContent="You belong to no other group this can move to."
				/>
				{preview && (
					<>
						<Typography.Text>
							From <strong>{labelOf(preview.from)}</strong> to{' '}
							<strong>{labelOf(preview.to)}</strong>
						</Typography.Text>
						{kind === 'bucket' && (
							<Typography.Text>
								{preview.projects && preview.projects.length > 0
									? `Moves with it: ${preview.projects.map((p) => p.name).join(', ')}.`
									: 'No project uses this bucket.'}
							</Typography.Text>
						)}
						<Alert
							type="info"
							showIcon
							title={preview.consequence}
						/>
					</>
				)}
			</Space>
		</Modal>
	);
}
