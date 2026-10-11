import { useEffect, useState } from 'react';
import { Button, Card, Modal, Select, Table, Typography } from 'antd';
import type { Project } from '../../../adapters/types.js';
import { request } from '../frame/request.js';
import { Link, useNavigate } from '../frame/router.js';
import { projectHref, projectSettingsHref } from '../frame/routes.js';
import type { BucketView } from './bucketView.js';

interface Declared {
	identifier: string;
	name: string;
	projectId: string;
	projectName: string;
}

interface Namespace {
	namespace: 'bucket' | 'root';
	resources: Declared[];
}

/*
 * The protected resources declared in a bucket's namespace, by any of its projects (specs/085). Read-only:
 * a resource is declared on its project, and this is where a collision between two projects of one bucket
 * becomes explainable.
 */
export function ProtectedResources({ bucket }: { bucket: BucketView }) {
	const [read, setRead] = useState<Namespace | null>(null);
	const [failed, setFailed] = useState(false);

	useEffect(() => {
		void (async () => {
			const result = await request<Namespace>(
				'GET',
				`/admin/api/buckets/${encodeURIComponent(bucket._id)}/resources`
			);
			if (result.ok) setRead(result.data);
			else setFailed(true);
		})();
	}, [bucket._id]);

	if (failed) return null;
	return (
		<Card title="Protected resources">
			{read?.namespace === 'root' && (
				<Typography.Paragraph type="secondary">
					This bucket has no address of its own, so its projects declare in the
					instance&apos;s shared root namespace. Only its own projects&apos;
					declarations are listed.
				</Typography.Paragraph>
			)}
			<Table<Declared>
				rowKey={(r) => `${r.projectId} ${r.identifier}`}
				size="small"
				loading={read === null}
				pagination={false}
				dataSource={read?.resources ?? []}
				locale={{
					emptyText:
						'No project declares a resource here. A resource is declared on a project’s Resources tab.'
				}}
				columns={[
					{
						title: 'Resource',
						dataIndex: 'identifier',
						render: (identifier: string, row: Declared) => (
							<>
								<Typography.Text strong>{row.name}</Typography.Text>
								<br />
								<Typography.Text code>{identifier}</Typography.Text>
							</>
						)
					},
					{
						title: 'Declared by',
						dataIndex: 'projectName',
						render: (name: string, row: Declared) => (
							<Link href={projectHref(row.projectId, 'resources')}>{name}</Link>
						)
					}
				]}
			/>
		</Card>
	);
}

/*
 * "Use in a project…" (specs/085): the bucket side only starts the change. The project owns the field, so
 * this picks a project of the bucket's group and opens its Bucket card with this bucket chosen, where the
 * server's preview says what the change does.
 */
export function UseInProject({ bucket }: { bucket: BucketView }) {
	const [open, setOpen] = useState(false);
	const [projects, setProjects] = useState<Project[] | null>(null);
	const [chosen, setChosen] = useState<string | undefined>();
	const navigate = useNavigate();

	useEffect(() => {
		if (!open || projects !== null) return;
		void (async () => {
			const result = await request<Project[]>('GET', '/admin/api/projects');
			setProjects(result.ok ? result.data : []);
		})();
	}, [open, projects]);

	// Only the projects the change route accepts: the bucket's own group's, not already using it.
	const offered = (projects ?? []).filter(
		(p) => p.ownerGroupId === bucket.ownerGroupId && p.bucketId !== bucket._id
	);

	return (
		<>
			<Button
				size="small"
				onClick={() => setOpen(true)}
			>
				Use in a project…
			</Button>
			<Modal
				open={open}
				title={`Use ${bucket.name} in a project`}
				okText="Continue"
				okButtonProps={{ disabled: !chosen }}
				onOk={() => {
					if (chosen) {
						void navigate(projectSettingsHref(chosen, { bucket: bucket._id }));
					}
				}}
				onCancel={() => setOpen(false)}
				destroyOnHidden
			>
				<Typography.Paragraph>
					A project&apos;s bucket is changed on the project. Continue opens its
					Bucket card with {bucket.name} chosen, where you see what the change
					does before anything happens.
				</Typography.Paragraph>
				<Select<string>
					style={{ width: '100%' }}
					placeholder="Project"
					loading={projects === null}
					value={chosen}
					onChange={setChosen}
					options={offered.map((p) => ({ value: p._id, label: p.name }))}
					notFoundContent="No other project of this bucket's group."
				/>
			</Modal>
		</>
	);
}
