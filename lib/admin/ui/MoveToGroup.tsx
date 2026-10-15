import { useEffect, useState } from 'react';
import { Alert, Select, Space, Typography } from 'antd';
import type { ScopeOption } from './pages/ScopeSwitcher.js';
import { groupLabel } from '../groups/label.js';
import { moveDestinations } from './ownership/model.js';
import { PreviewConfirm, type PreviewStep } from './frame/PreviewConfirm.js';
import { request } from './frame/request.js';

interface GroupRef {
	id: string;
	kind: ScopeOption['kind'] | null;
	name: string | null;
}

interface Preview {
	from: GroupRef;
	to: GroupRef;
	applications?: number;
	apis?: number;
	consequence: string;
}

/*
 * Moving a project, with everything it holds, to another team (specs/075, specs/099). Class
 * C4 (`bucket.move`).
 *
 * Two steps, because the server's preview is the only place the full list of what moves exists: the
 * first request names the destination and is answered with what would move; the second repeats it with
 * `confirm`. No typed word, unlike a deletion — nothing is destroyed, and a move can be moved back by
 * anyone who owns the group it lands in.
 */
export function MoveToGroup({
	id,
	name,
	sourceGroupId,
	onClose,
	onMoved
}: {
	id: string;
	name: string;
	sourceGroupId: string;
	onClose: () => void;
	onMoved: () => void;
}) {
	const [scope, setScope] = useState<ScopeOption[] | null>(null);
	const [scopeError, setScopeError] = useState<string | null>(null);
	const [groupId, setGroupId] = useState<string | null>(null);
	const [preview, setPreview] = useState<Preview | null>(null);

	useEffect(() => {
		void (async () => {
			const result = await request<{ available: ScopeOption[] }>(
				'GET',
				'/admin/api/scope'
			);
			if (result.ok) setScope(result.data.available);
			else setScopeError(result.error.message);
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

	async function step(commit: boolean): Promise<PreviewStep<Preview>> {
		const result = await request(
			'PUT',
			`/admin/api/projects/${encodeURIComponent(id)}/owner`,
			commit ? { teamId: groupId, confirm: true } : { teamId: groupId }
		);
		if (!result.ok) {
			// The preview arrives as a refusal: the server will not move anything it has not shown.
			if (result.status === 409 && result.error.confirmationRequired) {
				return {
					kind: 'preview',
					preview: result.error as unknown as Preview
				};
			}
			return { kind: 'failed', result };
		}
		return {
			kind: 'done',
			text: preview
				? `Project ${name} moved to ${labelOf(preview.to)}.`
				: `Project ${name} moved.`
		};
	}

	return (
		<PreviewConfirm<Preview>
			open
			title={`Move ${name} to another team`}
			commitText="Move"
			ready={groupId !== null}
			preview={preview}
			onPreview={setPreview}
			step={step}
			onClose={onClose}
			onDone={onMoved}
			renderPreview={(shown) => (
				<Space
					orientation="vertical"
					style={{ width: '100%', marginTop: 8 }}
				>
					<Typography.Text>
						From <strong>{labelOf(shown.from)}</strong> to{' '}
						<strong>{labelOf(shown.to)}</strong>
					</Typography.Text>
					<Typography.Text>
						{`Moves with it: ${String(shown.applications ?? 0)} application${shown.applications === 1 ? '' : 's'} and ${String(shown.apis ?? 0)} API${shown.apis === 1 ? '' : 's'}.`}
					</Typography.Text>
					<Alert
						type="info"
						showIcon
						title={shown.consequence}
					/>
				</Space>
			)}
		>
			{scopeError !== null ? (
				<Alert
					type="error"
					showIcon
					title={scopeError}
				/>
			) : (
				<Select
					placeholder="Destination team"
					loading={options === null}
					value={groupId ?? undefined}
					onChange={(value: string) => {
						setGroupId(value);
						// A preview computed for another destination is not one to agree to.
						setPreview(null);
					}}
					style={{ width: '100%' }}
					options={(options ?? []).map((g) => ({
						value: g.id,
						label: groupLabel(g)
					}))}
					notFoundContent="You belong to no other team this can move to."
				/>
			)}
		</PreviewConfirm>
	);
}
