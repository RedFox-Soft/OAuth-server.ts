import { useState, type ReactNode } from 'react';
import { Alert, Button, Card, Flex, Segmented, Table, Typography } from 'antd';
import {
	CheckCircleFilled,
	ClockCircleOutlined,
	ReloadOutlined
} from '@ant-design/icons';
import { useFeedback } from '../../frame/feedback.js';
import { Link } from '../../frame/router.js';
import { userGroupHref } from '../../frame/routes.js';
import type { GroupView } from '../groups/groupShared.js';
import {
	IDENTITY_HEADERS,
	PROXY_KINDS,
	recipeFor,
	type ProxyKind
} from '../../../../behind_proxy/recipes.js';
import {
	hostOfAddress,
	PROXY_LABELS,
	whenText,
	whoText,
	type AppView
} from './appView.js';

/* What each header tells the app. Keyed by the shared list, so a header added there cannot go unexplained here. */
const RECEIVES: Readonly<Record<(typeof IDENTITY_HEADERS)[number], string>> = {
	'X-Auth-User':
		"The person's account id in this project. Empty on a path open to anyone.",
	'X-Auth-Email':
		'Their email address; characters outside ASCII arrive percent-encoded (UTF-8). Empty on a public path.',
	'X-Auth-Groups':
		'The ids of their groups in this project, comma-separated. Empty on a public path.',
	'X-Auth-Assertion':
		"The same facts, with the groups' names, as a JWT signed with this project's keys for this address, valid for 60 seconds. Verify it when the app cannot be sure the request came through your proxy.",
	'X-Auth-Reason':
		'Why the request was let through: allowed, or public for a path open to anyone.'
};

function Step({
	n,
	title,
	at,
	children
}: {
	n: number;
	title: string;
	at: string | null;
	children: ReactNode;
}) {
	return (
		<Flex
			gap={12}
			align="start"
		>
			<span style={{ fontSize: 18, lineHeight: '24px' }}>
				{at ? (
					<CheckCircleFilled
						style={{ color: '#52c41a' }}
						aria-label="Done"
					/>
				) : (
					<ClockCircleOutlined
						style={{ color: '#8c8c8c' }}
						aria-label="Not yet"
					/>
				)}
			</span>
			<Flex
				vertical
				gap={2}
				style={{ flex: 1, minWidth: 0 }}
			>
				<Flex
					justify="space-between"
					wrap
					gap={8}
				>
					<Typography.Text strong>
						{n}. {title}
					</Typography.Text>
					{at && (
						<Typography.Text
							type="secondary"
							title={new Date(at).toLocaleString()}
						>
							{new Date(at).toLocaleString()} · {whenText(at)}
						</Typography.Text>
					)}
				</Flex>
				<div>{children}</div>
			</Flex>
		</Flex>
	);
}

/*
 * What it takes to put the app behind the proxy, and how far it has got (specs/122 FR-033). Each step says only what
 * the server saw: step 2 is "a request for this host reached this project", never "your proxy is set up", because a
 * proxy that sends the wrong host or none reaches nothing here at all.
 */
export function ConnectTab({
	bucketId,
	app,
	groups,
	onRefresh
}: {
	bucketId: string;
	app: AppView;
	groups: GroupView[];
	onRefresh: () => void;
}) {
	const feedback = useFeedback();
	const [kind, setKind] = useState<ProxyKind>(app.proxyKind);
	const host = hostOfAddress(app.address);
	const recipe = recipeFor(kind, {
		verifyUrl: app.verifyUrl,
		appAddress: app.address
	});
	const { checklist } = app;

	const root = app.rules.find((rule) => rule.path === '/');
	const rootGroups =
		root?.who.kind === 'groups'
			? root.who.groups.map(
					(g) =>
						groups.find((known) => known.id === g.id) ?? {
							id: g.id,
							displayName: g.name ?? 'Deleted group',
							memberCount: 0
						}
				)
			: [];
	const nobodyInRoot =
		root?.who.kind === 'groups' &&
		rootGroups.every((group) => group.memberCount === 0);

	async function copy() {
		try {
			await navigator.clipboard.writeText(recipe);
			feedback.done(`${PROXY_LABELS[kind]} configuration copied.`);
		} catch {
			feedback.refused({
				error: 'clipboard',
				message: 'The browser did not allow copying; select the text instead.'
			});
		}
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			<Card
				size="small"
				title="Getting it working"
				extra={
					<Button
						size="small"
						icon={<ReloadOutlined />}
						onClick={onRefresh}
					>
						Check again
					</Button>
				}
			>
				<Flex
					vertical
					gap={16}
				>
					<Step
						n={1}
						title="Created"
						at={checklist.createdAt}
					>
						<Typography.Text code>{host}</Typography.Text>
					</Step>
					<Step
						n={2}
						title="Your proxy asks this project"
						at={checklist.firstAskedAt}
					>
						<Flex
							vertical
							gap={8}
						>
							<Typography.Text type="secondary">
								{checklist.firstAskedAt
									? `A request for ${host} reached this project.${app.lastAskedAt ? ` Last asked ${whenText(app.lastAskedAt)}.` : ''}`
									: `Waiting for your proxy's first check for ${host}. Add the configuration below and reload the proxy.`}
							</Typography.Text>
							{app.mismatchedHosts.length > 0 && (
								<Alert
									type="warning"
									showIcon
									title={
										<>
											Your proxy asked about{' '}
											{app.mismatchedHosts.map((h, i) => (
												<span key={h}>
													{i > 0 && ', '}
													<Typography.Text code>{h}</Typography.Text>
												</span>
											))}{' '}
											for this app, which is not {host}.
										</>
									}
									description="Check that it passes the original host (X-Forwarded-Host) and that the app's address here is the one people open. Requests for another host are refused."
								/>
							)}
						</Flex>
					</Step>
					<Step
						n={3}
						title="Someone signs in through it"
						at={checklist.firstSignInAt}
					>
						<Typography.Text type="secondary">
							{checklist.firstSignInAt ? (
								'Someone completed a sign-in through the app.'
							) : (
								<>
									Open{' '}
									<Typography.Text
										code
										copyable={{ text: app.address }}
									>
										{app.address}
									</Typography.Text>{' '}
									in a private window and sign in.
								</>
							)}
						</Typography.Text>
					</Step>
					<Step
						n={4}
						title="Someone gets through"
						at={checklist.firstAllowedAt}
					>
						{checklist.firstAllowedAt ? (
							<Typography.Text type="secondary">
								A signed-in person was let through to the app.
							</Typography.Text>
						) : nobodyInRoot ? (
							<Typography.Text>
								{rootGroups.map((group, i) => (
									<span key={group.id}>
										{i > 0 && ', '}
										{group.displayName}: 0 members —{' '}
										<Link href={userGroupHref(bucketId, group.id)}>
											Add a person…
										</Link>
									</span>
								))}
							</Typography.Text>
						) : (
							<Typography.Text type="secondary">
								Waiting for someone who may open it to get through (
								{whoText(root?.who ?? null, () => null)}).
							</Typography.Text>
						)}
					</Step>
				</Flex>
			</Card>

			<Card
				size="small"
				title="Your proxy's configuration"
				extra={
					<Button
						size="small"
						onClick={() => void copy()}
					>
						Copy
					</Button>
				}
			>
				<Flex
					vertical
					gap={12}
				>
					<Segmented<ProxyKind>
						value={kind}
						onChange={setKind}
						options={PROXY_KINDS.map((k) => ({
							value: k,
							label: PROXY_LABELS[k]
						}))}
					/>
					<Typography.Text type="secondary">
						Your proxy calls{' '}
						<Typography.Text
							code
							copyable={{ text: app.verifyUrl }}
						>
							{app.verifyUrl}
						</Typography.Text>{' '}
						before each request. Replace the app's own address
						(http://127.0.0.1:8080) with where it listens.
					</Typography.Text>
					<pre
						style={{
							margin: 0,
							padding: 12,
							overflowX: 'auto',
							background: 'var(--ant-color-fill-quaternary, #f5f5f5)',
							borderRadius: 6,
							fontSize: 12
						}}
					>
						{recipe}
					</pre>
				</Flex>
			</Card>

			<Card
				size="small"
				title="What your app receives"
			>
				<Flex
					vertical
					gap={12}
				>
					<Alert
						type="info"
						showIcon
						title="Make sure the app can be reached only through your proxy."
						description="Anyone who reaches it directly can send these headers themselves. The configuration above removes them from every request before asking this project."
					/>
					<Table
						size="small"
						pagination={false}
						rowKey="header"
						dataSource={IDENTITY_HEADERS.map((header) => ({
							header,
							meaning: RECEIVES[header]
						}))}
						columns={[
							{
								title: 'Header',
								dataIndex: 'header',
								render: (header: string) => (
									<Typography.Text
										code
										style={{ whiteSpace: 'nowrap' }}
									>
										{header}
									</Typography.Text>
								)
							},
							{ title: 'What it holds', dataIndex: 'meaning' }
						]}
					/>
				</Flex>
			</Card>
		</Flex>
	);
}
