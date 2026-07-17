import { useState } from 'react';
import { Layout as AntLayout, Menu, Typography } from 'antd';
import type { MenuProps } from 'antd';
import {
	ProjectOutlined,
	TeamOutlined,
	SettingOutlined,
	KeyOutlined,
	LogoutOutlined
} from '@ant-design/icons';
import type { AdminContext } from '../../auth/rbac.js';
import { Projects } from './Projects.js';
import { Admins } from './Admins.js';
import { Stub } from './Stub.js';

const { Sider, Header, Content } = AntLayout;

type PageKey = 'projects' | 'admins' | 'settings' | 'keys';

export function Layout({ me }: { me: AdminContext | null }) {
	const roles = me?.roles ?? [];
	const isSuperAdmin = roles.includes('super_admin');
	const [selected, setSelected] = useState<PageKey>('projects');

	const items: MenuProps['items'] = [
		{ key: 'projects', icon: <ProjectOutlined />, label: 'Projects' },
		...(isSuperAdmin
			? [
					{ key: 'admins', icon: <TeamOutlined />, label: 'Admins' },
					{ key: 'settings', icon: <SettingOutlined />, label: 'Settings' },
					{ key: 'keys', icon: <KeyOutlined />, label: 'Keys' }
				]
			: [])
	];

	async function logout() {
		await fetch('/admin/api/logout', { method: 'POST' });
		window.location.href = '/admin/login';
	}

	function renderPage() {
		switch (selected) {
			case 'admins':
				return isSuperAdmin ? <Admins /> : <Projects />;
			case 'settings':
				return <Stub title="Settings" />;
			case 'keys':
				return <Stub title="Keys" />;
			default:
				return <Projects />;
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
					{me && <Typography.Text>{me.userId}</Typography.Text>}
					<a onClick={logout}>
						<LogoutOutlined /> Log out
					</a>
				</Header>
				<Content style={{ margin: 24 }}>{renderPage()}</Content>
			</AntLayout>
		</AntLayout>
	);
}
