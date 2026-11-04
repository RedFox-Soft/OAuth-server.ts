import { useEffect, useState } from 'react';
import { Button, List, Spin, Typography } from 'antd';
import type { UserBucket } from '../../../../adapters/types.js';
import { Link, useNavigate, useRoute } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { bucketCan, type BucketCan } from '../../frame/can.js';
import { PageHeader } from '../../frame/PageHeader.js';
import { LoadFailed } from '../../frame/states.js';
import { ADMIN_BUCKET_ID } from '../../../consts.js';
import {
	startDestination,
	type StartDestination
} from '../../../../situation_guide/start.js';

type Row = Pick<UserBucket, '_id' | 'name'> & {
	can?: Partial<BucketCan>;
	deletion?: unknown;
};

/*
 * The door for the site's buttons (`/admin/start?s=<id>`). The reader has signed in or registered by now; this
 * sends them to the guide's answer in their own project, or asks which project when they have several. It lands on
 * the guide and not on the form, because the guide is what says whether the form can be used here yet.
 */
export function StartPage() {
	const navigate = useNavigate();
	const { location } = useRoute();
	const [picks, setPicks] = useState<
		Extract<StartDestination, { kind: 'pick' }>['projects'] | null
	>(null);
	const [noProject, setNoProject] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [attempt, setAttempt] = useState(0);
	const search = location.search;

	useEffect(() => {
		let live = true;
		void request<Row[]>('GET', '/admin/api/projects').then((result) => {
			if (!live) return;
			if (!result.ok) {
				setError(result.error.message);
				return;
			}
			setError(null);
			const destination = startDestination(
				new URLSearchParams(search),
				result.data.map((row) => ({
					id: row._id,
					name: row.name,
					editable: bucketCan(row).edit,
					system: row._id === ADMIN_BUCKET_ID
				}))
			);
			if (destination.kind === 'go') {
				void navigate(destination.href, { replace: true });
			} else if (destination.kind === 'noProject') {
				setNoProject(true);
			} else {
				setPicks(destination.projects);
			}
		});
		return () => {
			live = false;
		};
	}, [search, navigate, attempt]);

	if (error !== null) {
		return (
			<LoadFailed
				reason={error}
				onRetry={() => setAttempt((n) => n + 1)}
			/>
		);
	}
	/*
	 * Said, not skipped: going to Projects silently would drop the answer the reader chose on the site. The address
	 * stays as it is, so the browser's Back returns here once a project exists.
	 */
	if (noProject) {
		return (
			<>
				<PageHeader title="Create a project first" />
				<Typography.Paragraph>
					What you chose on the site is set up inside a project, and you have no
					project you can change yet.
				</Typography.Paragraph>
				<Typography.Paragraph>
					Create one on Projects. Then open the link from the site again, and it
					takes you to the answer.
				</Typography.Paragraph>
				<Button
					type="primary"
					onClick={() => void navigate('/admin/projects')}
				>
					Go to Projects
				</Button>
			</>
		);
	}
	if (picks === null) {
		return (
			<div style={{ textAlign: 'center', padding: 48 }}>
				<Spin />
			</div>
		);
	}
	return (
		<>
			<PageHeader title="Which project?" />
			<Typography.Paragraph>
				Choose the project to set this up in.
			</Typography.Paragraph>
			<List
				bordered
				dataSource={picks}
				renderItem={(project) => (
					<List.Item>
						<Link href={project.href}>{project.name}</Link>
					</List.Item>
				)}
			/>
		</>
	);
}
