import { useEffect, useState } from 'react';
import { Layout as AntLayout, Badge, Button, Menu, Typography } from 'antd';
import type { MenuProps } from 'antd';
import {
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
import { request } from '../frame/request.js';
import { meCan, useMe } from '../frame/me.js';
import { sectionHref, type PageKey, type Section } from '../frame/routes.js';
import { InstanceOnly, NotFound } from '../frame/states.js';
import { BucketDetail, type BucketTab } from './BucketDetail.js';
import { AdminGroupPage } from './groups/AdminGroupPage.js';
import { UserPage, type UserTab } from './users/UserPage.js';
import { ProviderPage } from './providers/ProviderPage.js';
import {
	ConnectionPage,
	type ConnectionTab
} from './provisioning/ConnectionPage.js';
import { UserGroupPage } from './groups/UserGroupPage.js';
import {
	ApplicationPage,
	type ApplicationTab
} from './applications/ApplicationPage.js';
import { Groups } from './Groups.js';
import { ScopeSwitcher } from './ScopeSwitcher.js';
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
import { UsageBucketHistory } from './UsageBucketHistory.js';
import { ADMIN_BUCKET_ID } from '../../consts.js';

const { Sider, Header, Content } = AntLayout;

const BUCKET_TABS: Partial<Record<PageKey, BucketTab>> = {
	'bucket.overview': 'overview',
	'bucket.applications': 'applications',
	'bucket.apis': 'apis',
	'bucket.users': 'users',
	'bucket.userGroups': 'userGroups',
	'bucket.signIn': 'signIn',
	'bucket.providers': 'providers',
	'bucket.provisioning': 'provisioning',
	'bucket.outsideServers': 'outsideServers',
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

/* One application (spec 107); the bare address is its Connect tab. */
const APPLICATION_TABS: Partial<Record<PageKey, ApplicationTab>> = {
	'bucket.application': 'connect',
	'bucket.application.settings': 'settings'
};

/*
 * The console's frame: the sidebar, the header, and whichever page the address names. The page is chosen
 * by the route table (frame/routes.ts), never by state held here, so a link, a reload and the browser's
 * Back all land on the same screen.
 */
/*
 * How many provisioning connections the administrator can see are held (specs/088): a hold means removals are
 * not happening, so it is shown from every page rather than only from its project. Read again on every move
 * between pages, which is when the administrator would look at the menu anyway.
 */
function useHeldConnections(pathname: string): number {
	const [count, setCount] = useState(0);
	useEffect(() => {
		let live = true;
		void request<{ count: number }>(
			'GET',
			'/admin/api/provisioning-holds'
		).then((r) => {
			if (live && r.ok) setCount(r.data.count);
		});
		return () => {
			live = false;
		};
	}, [pathname]);
	return count;
}

export function Layout() {
	const { me } = useMe();
	const can = meCan(me);
	const { resolved, location } = useRoute();
	const navigate = useNavigate();
	const held = useHeldConnections(location.pathname);

	/*
	 * Grouped so an operator can tell their own work from the organisation around it and from the
	 * instance itself, which only a super administrator sees. Offered ⇔ permitted: Audit and Usage are open to
	 * every administrator because each is filtered to their teams rather than refused.
	 */
	const items: MenuProps['items'] = [
		{
			type: 'group',
			label: 'Build',
			children: [
				{
					key: 'projects',
					icon: <DatabaseOutlined />,
					label:
						held > 0 ? (
							<span
								title={`${held} provisioning connection${held === 1 ? ' is' : 's are'} on hold`}
							>
								Projects{' '}
								<Badge
									count={held}
									size="small"
								/>
							</span>
						) : (
							'Projects'
						)
				}
			]
		},
		{
			type: 'group',
			label: 'Organisation',
			children: [
				{ key: 'teams', icon: <ApartmentOutlined />, label: 'Teams' },
				{ key: 'audit', icon: <FileSearchOutlined />, label: 'Audit' },
				/* Every administrator's since specs/091: over the projects their teams own. */
				{ key: 'usage', icon: <LineChartOutlined />, label: 'Usage' }
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
					key={`${route.params.project ?? ''}/${route.params.user ?? ''}`}
					bucketId={route.params.project ?? ''}
					userId={route.params.user ?? ''}
					tab={userTab}
				/>
			);
		}
		const applicationTab = APPLICATION_TABS[route.key];
		if (applicationTab) {
			return (
				<ApplicationPage
					key={`${route.params.project ?? ''}/${route.params.client ?? ''}`}
					bucketId={route.params.project ?? ''}
					clientId={route.params.client ?? ''}
					tab={applicationTab}
				/>
			);
		}
		const connectionTab = CONNECTION_TABS[route.key];
		if (connectionTab) {
			return (
				<ConnectionPage
					key={`${route.params.project ?? ''}/${route.params.connection ?? ''}`}
					bucketId={route.params.project ?? ''}
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
					: (route.params.project ?? '');
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
					key={`${route.params.project ?? ''}/${route.params.group ?? ''}`}
					bucketId={route.params.project ?? ''}
					groupId={route.params.group ?? ''}
				/>
			);
		}
		const bucketTab = BUCKET_TABS[route.key];
		if (bucketTab) {
			return (
				<BucketDetail
					key={route.params.project}
					bucketId={route.params.project ?? ''}
					tab={bucketTab}
				/>
			);
		}
		switch (route.key) {
			case 'group':
				return (
					<AdminGroupPage
						key={route.params.team}
						groupId={route.params.team ?? ''}
					/>
				);
			case 'buckets':
				return <Buckets />;
			case 'groups':
				return <Groups currentUserId={me?.userId ?? null} />;
			case 'audit':
				return <Audit />;
			case 'usage':
				return <Usage superAdmin={can.instance} />;
			case 'usage.bucket':
				return (
					<UsageBucketHistory
						key={route.params.project}
						bucketId={route.params.project ?? ''}
					/>
				);
			case 'settings':
				return <Settings />;
			case 'keys':
				return <Keys />;
			case 'agentAccess':
				return <McpClients />;
			case 'faults':
				return <Errors />;
			default:
				return <Buckets />;
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
				{/* Keyed by the active team, so switching team remounts every list rather than leaving
				    half the console on the previous one. */}
				<Content
					key={me?.activeTeamId ?? 'none'}
					style={{ margin: 24 }}
				>
					{renderPage()}
				</Content>
			</AntLayout>
		</AntLayout>
	);
}
