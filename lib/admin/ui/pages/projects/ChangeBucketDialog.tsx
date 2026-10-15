import { useEffect, useState } from 'react';
import { Alert, Select, Space, Typography } from 'antd';
import type { UserBucket } from '../../../../adapters/types.js';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from '../../../consts.js';
import { assignableBuckets } from '../../projects/model.js';
import {
	PreviewConfirm,
	type PreviewStep
} from '../../frame/PreviewConfirm.js';
import { request } from '../../frame/request.js';
import { meCan, useMe } from '../../frame/me.js';
import type { ProjectView } from '../ProjectWorkspace.js';

interface BucketEnd {
	bucketId: string;
	name: string;
	issuer: string | null;
}

/* The server's preview of a bucket change (specs/085), answered as a 409 until it is confirmed. */
export interface BucketChangePreview {
	from: BucketEnd;
	to: BucketEnd;
	applications: { clientId: string; name: string | null }[];
	resources: { identifier: string; name: string }[];
	conflicts: string[];
	rootRefused: boolean;
	blocked: boolean;
	consequence: string;
	expect: { applications: number; resources: number };
}

function plural(n: number, one: string, many: string): string {
	return `${String(n)} ${n === 1 ? one : many}`;
}

/*
 * Changing a project's bucket (C4 `project.bucket.change`). There is no removing one (specs/098): a project
 * always signs people in from some bucket, and only a super administrator may choose the shared Default one.
 *
 * The change gives every application of the project a new issuer and signs everyone in it out, and only the
 * server holds the whole list, so the first request names the destination and is answered with the preview;
 * the second repeats it with `confirm` and the counts the operator saw. A change that would collide with a
 * resource already declared in the destination is shown and cannot be confirmed.
 */
export function ChangeBucketDialog({
	project,
	preselect,
	onClose,
	onChanged
}: {
	project: ProjectView;
	preselect?: string;
	onClose: () => void;
	onChanged: () => void;
}) {
	const [buckets, setBuckets] = useState<UserBucket[] | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [bucketId, setBucketId] = useState<string | null>(
		preselect && preselect !== project.bucketId ? preselect : null
	);
	const [preview, setPreview] = useState<BucketChangePreview | null>(null);
	// Set when a confirm met a preview that had changed since it was shown.
	const [changedMeanwhile, setChangedMeanwhile] = useState(false);
	const { me } = useMe();

	useEffect(() => {
		void (async () => {
			const result = await request<UserBucket[]>('GET', '/admin/api/buckets');
			if (result.ok) setBuckets(result.data);
			else setLoadError(result.error.message);
		})();
	}, []);

	/*
	 * Only the buckets the route accepts: the project's own group's, never the console's — and the shared
	 * Default bucket to a super administrator alone, the one bucket a project of any group may use.
	 */
	const offered = [
		...assignableBuckets(buckets ?? [], project)
			.filter(
				(b) =>
					b._id !== project.bucketId &&
					b._id !== ADMIN_BUCKET_ID &&
					b._id !== DEFAULT_BUCKET_ID
			)
			.map((b) => ({ value: b._id, label: b.name })),
		...(meCan(me).instance && project.bucketId !== DEFAULT_BUCKET_ID
			? [{ value: DEFAULT_BUCKET_ID, label: 'Default bucket (shared)' }]
			: [])
	];

	async function step(
		commit: boolean
	): Promise<PreviewStep<BucketChangePreview>> {
		const base = `/admin/api/projects/${encodeURIComponent(project._id)}/bucket`;
		const confirmation =
			commit && preview ? { confirm: true, expect: preview.expect } : {};
		const result = await request('PUT', base, { bucketId, ...confirmation });
		if (!result.ok) {
			if (result.status === 409 && result.error.confirmationRequired) {
				setChangedMeanwhile(commit);
				return {
					kind: 'preview',
					preview: result.error as unknown as BucketChangePreview
				};
			}
			return { kind: 'failed', result };
		}
		return {
			kind: 'done',
			text: `${project.name} now uses ${preview?.to.name ?? 'the new bucket'}.`
		};
	}

	const title = `Change the bucket of ${project.name}`;

	return (
		<PreviewConfirm<BucketChangePreview>
			open
			title={title}
			nextText="Next"
			commitText="Change bucket"
			danger={preview !== null && preview.applications.length > 0}
			ready={bucketId !== null && !(preview?.blocked ?? false)}
			preview={preview}
			onPreview={setPreview}
			step={step}
			onClose={onClose}
			onDone={onChanged}
			renderPreview={(shown) => (
				<BucketChangeSummary
					preview={shown}
					changedMeanwhile={changedMeanwhile}
				/>
			)}
		>
			{loadError !== null ? (
				<Alert
					type="error"
					showIcon
					title={loadError}
				/>
			) : (
				<Space
					orientation="vertical"
					style={{ width: '100%' }}
				>
					<Select<string>
						style={{ width: '100%' }}
						placeholder="Choose a bucket"
						loading={buckets === null}
						value={bucketId ?? undefined}
						onChange={(value) => {
							setBucketId(value);
							// A preview computed for another bucket is not one to agree to.
							setPreview(null);
							setChangedMeanwhile(false);
						}}
						options={offered}
						notFoundContent="No other bucket belongs to this project's group."
					/>
					<Typography.Text type="secondary">
						Only buckets of the project&apos;s own group are offered. To use a
						bucket of another group, move that bucket to this group first.
					</Typography.Text>
				</Space>
			)}
		</PreviewConfirm>
	);
}

function BucketChangeSummary({
	preview,
	changedMeanwhile
}: {
	preview: BucketChangePreview;
	changedMeanwhile: boolean;
}) {
	const { applications, resources, conflicts } = preview;
	return (
		<Space
			orientation="vertical"
			style={{ width: '100%', marginTop: 8 }}
		>
			{changedMeanwhile && (
				<Alert
					type="warning"
					showIcon
					title="Something changed since the preview. This is what the change does now."
				/>
			)}
			<Typography.Text>
				From <strong>{preview.from.name}</strong> to{' '}
				<strong>{preview.to.name}</strong>
			</Typography.Text>
			{applications.length === 0 ? (
				<Typography.Text>
					The project has no applications, so nobody is signed out.
				</Typography.Text>
			) : (
				<>
					<Typography.Text>
						{plural(
							applications.length,
							'application gets',
							'applications get'
						)}{' '}
						a new issuer:
					</Typography.Text>
					<Typography.Text code>
						{preview.from.issuer ?? 'no address'}
					</Typography.Text>
					<Typography.Text code>
						{preview.to.issuer ?? 'no address'}
					</Typography.Text>
					<ul
						style={{
							margin: 0,
							paddingInlineStart: 20,
							maxHeight: 180,
							overflowY: 'auto'
						}}
					>
						{applications.map((a) => (
							<li key={a.clientId}>
								{a.name ?? a.clientId}
								{a.name !== null && (
									<Typography.Text type="secondary">
										{' '}
										· {a.clientId}
									</Typography.Text>
								)}
							</li>
						))}
					</ul>
					<ul style={{ margin: 0, paddingInlineStart: 20 }}>
						<li>
							People signed in through them must sign in again, with an account
							of {preview.to.name}. Accounts do not move between buckets.
						</li>
						<li>Tokens already issued keep working until they expire.</li>
						<li>
							An integration that checks the issuer must be updated to the new
							one.
						</li>
					</ul>
				</>
			)}
			{resources.length > 0 && (
				<Typography.Text>
					{plural(
						resources.length,
						'declared resource moves',
						'declared resources move'
					)}{' '}
					to {preview.to.name}&apos;s namespace:{' '}
					{resources.map((r) => r.identifier).join(', ')}
				</Typography.Text>
			)}
			{conflicts.length > 0 && (
				<Alert
					type="error"
					showIcon
					title={`${preview.to.name} already declares ${conflicts.join(', ')}. Remove or rename it in one of the projects before changing the bucket.`}
				/>
			)}
			{preview.rootRefused && (
				<Alert
					type="error"
					showIcon
					title="Its declared resources would move to the shared root namespace, where only an instance administrator may declare. Ask one, or remove the declarations first."
				/>
			)}
		</Space>
	);
}
