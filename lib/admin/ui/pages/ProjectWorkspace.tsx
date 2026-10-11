import { useEffect, useState } from 'react';
import { Skeleton } from 'antd';
import type { Project } from '../../../adapters/types.js';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { LoadFailed, NoAccess } from '../frame/states.js';
import { projectHref } from '../frame/routes.js';
import type { ProjectBlockers, ProjectCan } from '../frame/can.js';
import { Clients } from './Clients.js';
import { Resources } from './Resources.js';
import { ProjectSettings } from './projects/ProjectSettings.js';

/* A project as the admin API answers it: the record, the caller's stated rights over it, and its blockers. */
export type ProjectView = Project & {
	can?: Partial<ProjectCan>;
	blockers?: Partial<ProjectBlockers>;
	// The bucket it signs people into and how many applications it has, stated by the row (specs/085).
	bucket?: {
		id: string;
		name: string;
		addressForm: 'root' | 'path' | 'host' | 'unaddressed';
	} | null;
	clientCount?: number;
};

/*
 * A project at its own address. The project is read by id here rather than handed down from the list,
 * so the page opens the same way from a link, a reload, or the list — which is the point of having an
 * address at all.
 */
export function ProjectWorkspace({
	projectId,
	area
}: {
	projectId: string;
	area: 'clients' | 'resources' | 'settings';
}) {
	// Keyed by project in Layout, so another project's address mounts afresh rather than showing this one.
	const [project, setProject] = useState<ProjectView | null>(null);
	const [status, setStatus] = useState<number | null>(null);

	// Bumped by Retry, which re-runs the read below.
	const [attempt, setAttempt] = useState(0);

	useEffect(() => {
		let current = true;
		void request<ProjectView>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(projectId)}`
		).then((result) => {
			if (!current) return;
			if (result.ok) setProject(result.data);
			else setStatus(result.status);
		});
		return () => {
			current = false;
		};
	}, [projectId, attempt]);

	if (status !== null) {
		return status === 403 || status === 404 ? (
			<NoAccess
				what="project"
				backHref="/admin/projects"
				backLabel="Back to Projects"
			/>
		) : (
			<LoadFailed
				onRetry={() => {
					setStatus(null);
					setAttempt((n) => n + 1);
				}}
			/>
		);
	}
	if (!project) return <Skeleton active />;

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Projects', href: '/admin/projects' },
					{ label: project.name }
				]}
				title={project.name}
				tabs={[
					{
						key: 'clients',
						label: 'Clients',
						href: projectHref(project._id, 'clients')
					},
					{
						key: 'resources',
						label: 'Resources',
						href: projectHref(project._id, 'resources')
					},
					{
						key: 'settings',
						label: 'Settings',
						href: projectHref(project._id, 'settings')
					}
				]}
				activeTab={area}
			/>
			{area === 'clients' && <Clients project={project} />}
			{area === 'resources' && <Resources project={project} />}
			{area === 'settings' && (
				<ProjectSettings
					project={project}
					onChanged={() => setAttempt((n) => n + 1)}
				/>
			)}
		</>
	);
}
