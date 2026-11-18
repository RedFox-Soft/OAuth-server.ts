import { useEffect, useState } from 'react';
import { Typography } from 'antd';
import { PageHeader } from '../../frame/PageHeader.js';
import { request } from '../../frame/request.js';
import { ActivityTimeline } from '../users/UserActivityTab.js';

interface AdminListRow {
	_id: string;
	email: string;
}

/*
 * One administrator's sign-ins (specs/137 contracts/console.md), for a super administrator: the timeline a person's
 * Activity tab shows, over the administrators' project, where only sign-ins are kept. The email comes from the
 * Accounts list, a few tens of rows, rather than a route of its own.
 */
export function AdminSignInsPage({ adminId }: { adminId: string }) {
	const [email, setEmail] = useState<string | null>(null);
	useEffect(() => {
		void request<AdminListRow[]>('GET', '/admin/api/admins').then((result) => {
			if (result.ok) {
				setEmail(result.data.find((row) => row._id === adminId)?.email ?? null);
			}
		});
	}, [adminId]);
	const href = `/admin/administrators/sign-ins/${encodeURIComponent(adminId)}`;
	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Administrators', href: '/admin/administrators' },
					{ label: 'Accounts', href: '/admin/administrators' },
					{ label: 'Sign-ins' }
				]}
				title={`Sign-ins of ${email ?? 'an administrator'}`}
				description={
					<Typography.Text type="secondary">
						Each time you open this list, the audit trail records that you read
						it, once a day.
					</Typography.Text>
				}
			/>
			<ActivityTimeline
				endpoint={`/admin/api/admins/${encodeURIComponent(adminId)}/activity`}
				href={href}
				signInsOnly
			/>
		</>
	);
}
