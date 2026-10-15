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
	projects?: Array<{ id: string; name: string }>;
	consequence: string;
}

/*
 * Moving a bucket, with the projects using it, or a project on the Default bucket, to another administrator
 * group (specs/075). Class C4 (`bucket.move`, `project.move`).
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
			`/admin/api/${kind === 'bucket' ? 'buckets' : 'projects'}/${encodeURIComponent(id)}/owner`,
			commit ? { groupId, confirm: true } : { groupId }
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
		const noun = kind === 'bucket' ? 'Bucket' : 'Project';
		return {
			kind: 'done',
			text: preview
				? `${noun} ${name} moved to ${labelOf(preview.to)}.`
				: `${noun} ${name} moved.`
		};
	}

	return (
		<PreviewConfirm<Preview>
			open
			title={`Move ${name} to another group`}
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
					{kind === 'bucket' && (
						<Typography.Text>
							{shown.projects && shown.projects.length > 0
								? `Moves with it: ${shown.projects.map((p) => p.name).join(', ')}.`
								: 'No project uses this bucket.'}
						</Typography.Text>
					)}
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
					placeholder="Destination group"
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
					notFoundContent="You belong to no other group this can move to."
				/>
			)}
		</PreviewConfirm>
	);
}
