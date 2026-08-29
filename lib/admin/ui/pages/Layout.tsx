import { useState } from 'react';
import { Layout as AntLayout, Menu, Typography } from 'antd';
import type { MenuProps } from 'antd';
import {
	ProjectOutlined,
	DatabaseOutlined,
	TeamOutlined,
	ApartmentOutlined,
	SettingOutlined,
	KeyOutlined,
	FileSearchOutlined,
	BugOutlined,
	LogoutOutlined
} from '@ant-design/icons';
import type { AdminContext } from '../../auth/rbac.js';
import { Groups } from './Groups.js';
import { ScopeSwitcher } from './ScopeSwitcher.js';
import { Projects } from './Projects.js';
import { Buckets } from './Buckets.js';
import { Admins } from './Admins.js';
import { Settings } from './Settings.js';
import { Keys } from './Keys.js';
import { Audit } from './Audit.js';
import { Errors } from './Errors.js';

const { Sider, Header, Content } = AntLayout;

type PageKey =
	| 'projects'
	| 'buckets'
	| 'groups'
	| 'admins'
	| 'settings'
	| 'keys'
	| 'audit'
	| 'errors';

export function Layout({ me }: { me: AdminContext | null }) {
	const roles = me?.roles ?? [];
	const isSuperAdmin = roles.includes('super_admin');
	const [selected, setSelected] = useState<PageKey>('projects');

	/*
	 * Offered ⇔ permitted, in both directions. The create actions below are no longer role-gated, and
	 * Audit has moved out of the super-admin block because it is scope-filtered rather than refused: a
	 * group reads its own history. What remains super-admin-only is the instance itself.
	 */
	const items: MenuProps['items'] = [
		{ key: 'projects', icon: <ProjectOutlined />, label: 'Projects' },
		{ key: 'buckets', icon: <DatabaseOutlined />, label: 'Buckets' },
		{ key: 'groups', icon: <ApartmentOutlined />, label: 'Groups' },
		{ key: 'audit', icon: <FileSearchOutlined />, label: 'Audit' },
		...(isSuperAdmin
			? [
					{ key: 'admins', icon: <TeamOutlined />, label: 'Admins' },
					{ key: 'settings', icon: <SettingOutlined />, label: 'Settings' },
					{ key: 'keys', icon: <KeyOutlined />, label: 'Keys' },
					{ key: 'errors', icon: <BugOutlined />, label: 'Faults' }
				]
			: [])
	];

	async function logout() {
		// Navigate even if the request failed. Leaving the operator on a panel they believe they
		// have left is the worse of the two outcomes: the sign-in redirect re-checks the session
		// either way, so a failed logout surfaces as being asked to sign in again.
		try {
			await fetch('/admin/api/logout', { method: 'POST' });
		} finally {
			window.location.href = '/admin/login';
		}
	}

	function renderPage() {
		switch (selected) {
			case 'buckets':
				return <Buckets isSuperAdmin={isSuperAdmin} />;
			case 'admins':
				return isSuperAdmin ? (
					<Admins />
				) : (
					<Projects isSuperAdmin={isSuperAdmin} />
				);
			case 'settings':
				return isSuperAdmin ? (
					<Settings />
				) : (
					<Projects isSuperAdmin={isSuperAdmin} />
				);
			case 'keys':
				return isSuperAdmin ? (
					<Keys />
				) : (
					<Projects isSuperAdmin={isSuperAdmin} />
				);
			case 'groups':
				return (
					<Groups
						isSuperAdmin={isSuperAdmin}
						currentUserId={me?.userId ?? null}
					/>
				);
			// Scope-filtered rather than refused: every administrator reads the trail of the groups they
			// belong to, so this no longer falls back to Projects for a non-super-admin.
			case 'audit':
				return <Audit />;
			case 'errors':
				return isSuperAdmin ? (
					<Errors />
				) : (
					<Projects isSuperAdmin={isSuperAdmin} />
				);
			default:
				return <Projects isSuperAdmin={isSuperAdmin} />;
		}
	}

	return (
		<AntLayout style={{ minHeight: '100vh' }}>
			<Sider>
				<div style={{ color: '#fff', padding: 16, fontWeight: 600 }}>
					OAuth Admin
				</div>
				<Menu
					theme="dark"
					mode="inline"
					selectedKeys={[selected]}
					items={items}
					onClick={({ key }) => setSelected(key as PageKey)}
				/>
			</Sider>
			<AntLayout>
				<Header
					style={{
						background: '#fff',
						display: 'flex',
						justifyContent: 'flex-end',
						alignItems: 'center',
						gap: 12
					}}
				>
					<ScopeSwitcher />
					{me && <Typography.Text>{me.email}</Typography.Text>}
					<a onClick={logout}>
						<LogoutOutlined /> Log out
					</a>
				</Header>
				<Content style={{ margin: 24 }}>{renderPage()}</Content>
			</AntLayout>
		</AntLayout>
	);
}
