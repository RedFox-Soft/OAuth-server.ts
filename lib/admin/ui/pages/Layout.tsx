import { Layout as AntLayout, Button, Menu, Typography } from 'antd';
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
	LineChartOutlined,
	RobotOutlined,
	LogoutOutlined
} from '@ant-design/icons';
import { useNavigate, useRoute } from '../frame/router.js';
import { meCan, useMe } from '../frame/me.js';
import { sectionHref, type PageKey, type Section } from '../frame/routes.js';
import { InstanceOnly, NotFound } from '../frame/states.js';
import { BucketDetail, type BucketTab } from './BucketDetail.js';
import { ProjectWorkspace } from './ProjectWorkspace.js';
import { AdminGroupPage } from './groups/AdminGroupPage.js';
import { UserPage, type UserTab } from './users/UserPage.js';
import { ProviderPage } from './providers/ProviderPage.js';
import {
	ConnectionPage,
	type ConnectionTab
} from './provisioning/ConnectionPage.js';
import { UserGroupPage } from './groups/UserGroupPage.js';
import { Groups } from './Groups.js';
import { ScopeSwitcher } from './ScopeSwitcher.js';
import { Projects } from './Projects.js';
import { Buckets } from './Buckets.js';
import {
	AdministratorsHome,
	type AdministratorsTab
} from './administrators/AdministratorsHome.js';
import { Settings } from './Settings.js';
import { Keys } from './Keys.js';
import { McpClients } from './McpClients.js';
import { Audit } from './Audit.js';
import { Errors } from './Errors.js';
import { Usage } from './Usage.js';
import { ADMIN_BUCKET_ID } from '../../consts.js';

const PROJECT_AREAS = {
	'project.clients': 'clients',
	'project.resources': 'resources',
	'project.settings': 'settings'
} as const;

const { Sider, Header, Content } = AntLayout;

const BUCKET_TABS: Partial<Record<PageKey, BucketTab>> = {
	'bucket.overview': 'overview',
	'bucket.users': 'users',
	'bucket.userGroups': 'userGroups',
	'bucket.signIn': 'signIn',
	'bucket.providers': 'providers',
	'bucket.provisioning': 'provisioning',
	'bucket.keys': 'keys',
	'bucket.activity': 'activity',
	'bucket.settings': 'settings'
};

/* The console's own bucket, at home with its accounts (specs/083). */
const ADMINISTRATORS_TABS: Partial<Record<PageKey, AdministratorsTab>> = {
	administrators: 'accounts',
	'administrators.signIn': 'signIn',
	'administrators.providers': 'providers',
	'administrators.activity': 'activity',
	'administrators.settings': 'settings'
};

/* One person in a bucket (specs/082): its own page, beside the bucket's areas rather than inside them. */
const USER_TABS: Partial<Record<PageKey, UserTab>> = {
	'bucket.user': 'profile',
	'bucket.user.signIn': 'signIn',
	'bucket.user.groups': 'groups',
	'bucket.user.activity': 'activity'
};

/* One provisioning connection (specs/084); the bare address is its Overview, which the hold email links to. */
const CONNECTION_TABS: Partial<Record<PageKey, ConnectionTab>> = {
	'bucket.connection': 'overview',
	'bucket.connection.setup': 'setup',
	'bucket.connection.settings': 'settings'
};

/*
 * The console's frame: the sidebar, the header, and whichever page the address names. The page is chosen
 * by the route table (frame/routes.ts), never by state held here, so a link, a reload and the browser's
 * Back all land on the same screen.
 */
export function Layout() {
	const { me } = useMe();
	const can = meCan(me);
	const { resolved } = useRoute();
	const navigate = useNavigate();

	/*
	 * Grouped so an operator can tell their own work from the organisation around it and from the
	 * instance itself, which only a super administrator sees. Offered ⇔ permitted: Audit is open to every
	 * administrator because it is filtered to their groups rather than refused.
	 */
	const items: MenuProps['items'] = [
		{
			type: 'group',
			label: 'Build',
			children: [
				{ key: 'projects', icon: <ProjectOutlined />, label: 'Projects' },
				{ key: 'buckets', icon: <DatabaseOutlined />, label: 'Buckets' }
			]
		},
		{
			type: 'group',
			label: 'Organisation',
			children: [
				{ key: 'groups', icon: <ApartmentOutlined />, label: 'Groups' },
				{ key: 'audit', icon: <FileSearchOutlined />, label: 'Audit' }
			]
		},
		...(can.instance
			? [
					{
						type: 'group' as const,
						label: 'Instance',
						children: [
							{
								key: 'administrators',
								icon: <TeamOutlined />,
								label: 'Administrators'
							},
							{ key: 'usage', icon: <LineChartOutlined />, label: 'Usage' },
							{ key: 'settings', icon: <SettingOutlined />, label: 'Settings' },
							{ key: 'keys', icon: <KeyOutlined />, label: 'Keys' },
							{
								key: 'agent-access',
								icon: <RobotOutlined />,
								label: 'Agent access'
							},
							{ key: 'faults', icon: <BugOutlined />, label: 'Faults' }
						]
					}
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
		if (resolved.kind === 'redirect') return null;
		if (resolved.kind === 'none') return <NotFound />;
		const { route } = resolved;
		if (route.instance && !can.instance) return <InstanceOnly />;
		const administratorsTab = ADMINISTRATORS_TABS[route.key];
		if (administratorsTab) {
			return <AdministratorsHome tab={administratorsTab} />;
		}
		const userTab = USER_TABS[route.key];
		if (userTab) {
			return (
				<UserPage
					key={`${route.params.bucket ?? ''}/${route.params.user ?? ''}`}
					bucketId={route.params.bucket ?? ''}
					userId={route.params.user ?? ''}
					tab={userTab}
				/>
			);
		}
		const connectionTab = CONNECTION_TABS[route.key];
		if (connectionTab) {
			return (
				<ConnectionPage
					key={`${route.params.bucket ?? ''}/${route.params.connection ?? ''}`}
					bucketId={route.params.bucket ?? ''}
					connectionId={route.params.connection ?? ''}
					tab={connectionTab}
				/>
			);
		}
		if (
			route.key === 'bucket.provider' ||
			route.key === 'administrators.provider'
		) {
			// The console's own bucket keeps its providers under Administrators (specs/083).
			const bucketId =
				route.key === 'administrators.provider'
					? ADMIN_BUCKET_ID
					: (route.params.bucket ?? '');
			return (
				<ProviderPage
					key={`${bucketId}/${route.params.provider ?? ''}`}
					bucketId={bucketId}
					providerId={route.params.provider ?? ''}
				/>
			);
		}
		if (route.key === 'bucket.userGroup') {
			return (
				<UserGroupPage
					key={`${route.params.bucket ?? ''}/${route.params.group ?? ''}`}
					bucketId={route.params.bucket ?? ''}
					groupId={route.params.group ?? ''}
				/>
			);
		}
		const bucketTab = BUCKET_TABS[route.key];
		if (bucketTab) {
			return (
				<BucketDetail
					key={route.params.bucket}
					bucketId={route.params.bucket ?? ''}
					tab={bucketTab}
				/>
			);
		}
		switch (route.key) {
			case 'project.clients':
			case 'project.resources':
			case 'project.settings':
				return (
					<ProjectWorkspace
						key={route.params.project}
						projectId={route.params.project ?? ''}
						area={PROJECT_AREAS[route.key]}
					/>
				);
			case 'group':
				return (
					<AdminGroupPage
						key={route.params.group}
						groupId={route.params.group ?? ''}
					/>
				);
			case 'buckets':
				return <Buckets />;
			case 'groups':
				return <Groups currentUserId={me?.userId ?? null} />;
			case 'audit':
				return <Audit />;
			case 'usage':
				return <Usage />;
			case 'settings':
				return <Settings />;
			case 'keys':
				return <Keys />;
			case 'agentAccess':
				return <McpClients />;
			case 'faults':
				return <Errors />;
			default:
				return <Projects />;
		}
	}

	const selected =
		resolved.kind === 'page' && resolved.route.section
			? [resolved.route.section]
			: [];

	return (
		<AntLayout style={{ minHeight: '100vh' }}>
			<Sider
				breakpoint="lg"
				collapsedWidth={0}
			>
				<div style={{ color: '#fff', padding: 16, fontWeight: 600 }}>
					OAuth Admin
				</div>
				{/* A fixed id: the generated one differs between the server render and the hydrate under test. */}
				<Menu
					id="console-menu"
					theme="dark"
					mode="inline"
					selectedKeys={selected}
					items={items}
					onClick={({ key }) => void navigate(sectionHref(key as Section))}
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
					<Button
						type="link"
						icon={<LogoutOutlined />}
						onClick={() => void logout()}
					>
						Log out
					</Button>
				</Header>
				{/* Keyed by the active group, so switching group remounts every list rather than leaving
				    half the console on the previous one. */}
				<Content
					key={me?.activeGroupId ?? 'none'}
					style={{ margin: 24 }}
				>
					{renderPage()}
				</Content>
			</AntLayout>
		</AntLayout>
	);
}
