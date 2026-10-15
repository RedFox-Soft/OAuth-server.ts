import { useEffect, useState, type ReactNode } from 'react';
import {
	Alert,
	Button,
	Card,
	Col,
	Descriptions,
	Flex,
	Row,
	Statistic,
	Typography
} from 'antd';
import { Link, useNavigate } from '../frame/router.js';
import { bucketHref, connectionHref } from '../frame/routes.js';
import { request } from '../frame/request.js';
import type { BucketCan } from '../frame/can.js';
import { UNASSIGNED_GROUP_ID, reservedOf } from '../../consts.js';
import type { BucketSummary, BucketView } from './bucketView.js';
import { RecentChanges } from '../frame/RecentChanges.js';
import { BucketPlanCard } from './BucketPlanCard.js';

/*
 * A bucket's landing page (specs/081): what needs attention, how to connect an application to it, how people
 * sign in, and how many there are. It reads what the bucket read and the summary already say and edits
 * nothing — every change is one click away on the tab that owns it, so there is never a second editor.
 */

const ADDRESS_FORM: Record<NonNullable<BucketView['addressForm']>, string> = {
	root: "Served at the server's root",
	path: 'A path of the server',
	subdomain: 'A subdomain of the server',
	host: 'A hostname of its own',
	unaddressed: 'No address of its own'
};

interface Attention {
	key: string;
	type: 'error' | 'warning' | 'info';
	title: string;
	action: ReactNode;
}

function plural(n: number, one: string, many: string): string {
	return `${String(n)} ${n === 1 ? one : many}`;
}

export function BucketOverview({
	bucket,
	summary,
	summaryFailed,
	can,
	superAdmin,
	groupName,
	onOpenSignIn,
	onChanged
}: {
	bucket: BucketView;
	summary: BucketSummary | null;
	summaryFailed: boolean;
	can: BucketCan;
	superAdmin: boolean;
	groupName: string;
	onOpenSignIn: () => void;
	/* The project moved to another plan; the page reads it and its summary again. */
	onChanged: () => void;
}) {
	const navigate = useNavigate();
	const special = reservedOf(bucket._id);
	/*
	 * The connections, for two items: the held one, so the item opens the page that can end the hold (specs/084
	 * US6), and a static token about to expire (specs/088). The list is short; a caller who may not read it gets
	 * neither item, and the summary still says a hold exists.
	 */
	const [connections, setConnections] = useState<
		{
			id: string;
			displayName: string;
			hold?: unknown;
			warnings: string[];
			staticToken: { expiresAt: string } | null;
		}[]
	>([]);
	useEffect(() => {
		let live = true;
		void request<typeof connections>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(bucket._id)}/provisioning-connections`
		).then((r) => {
			if (live && r.ok) setConnections(r.data);
		});
		return () => {
			live = false;
		};
	}, [bucket._id]);
	const heldId = connections.find((c) => c.hold)?.id ?? null;
	const expiring = connections.filter(
		(c) =>
			c.warnings.includes('static_token_expiring') ||
			c.warnings.includes('static_token_expired')
	);
	const settingsHref = bucketHref(bucket._id, 'settings');
	const applications = bucket.applications ?? 0;
	const apis = bucket.apis ?? 0;

	/* In the order of FR-003: what stops people first, what only looks odd last. */
	const attention: Attention[] = [];
	if (summary && summary.held > 0) {
		attention.push({
			key: 'held',
			type: 'error',
			title: `${plural(summary.held, 'provisioning connection is', 'provisioning connections are')} holding a mass deprovisioning.`,
			action: (
				<Button
					size="small"
					onClick={() =>
						void navigate(
							heldId
								? connectionHref(bucket._id, heldId)
								: bucketHref(bucket._id, 'provisioning')
						)
					}
				>
					{heldId ? 'Review the hold' : 'Open Provisioning'}
				</Button>
			)
		});
	}
	for (const c of expiring) {
		const expired = c.warnings.includes('static_token_expired');
		attention.push({
			key: `token-${c.id}`,
			type: expired ? 'error' : 'warning',
			title: expired
				? `The static token of ${c.displayName} has expired: the directory's requests are refused.`
				: `The static token of ${c.displayName} expires ${c.staticToken ? new Date(c.staticToken.expiresAt).toLocaleDateString() : 'soon'}. Replace it: the current one keeps working until the directory uses the new one.`,
			action: (
				<Button
					size="small"
					onClick={() => void navigate(connectionHref(bucket._id, c.id))}
				>
					Open connection
				</Button>
			)
		});
	}
	if (bucket.address && !bucket.address.requestsArrived) {
		attention.push({
			key: 'host',
			type: 'warning',
			/*
			 * A subdomain has no record of its own to create: the instance's wildcard covers every one, so
			 * asking for a per-project record would send the operator to do something that cannot help.
			 */
			title: bucket.address.dnsRecord.shared
				? `No request has reached ${bucket.address.host} yet. It is reached through this instance's wildcard DNS record ${bucket.address.dnsRecord.name} and its certificate, which must exist for any subdomain project to answer.`
				: `No request has reached ${bucket.address.host} yet. Create the DNS record so applications can reach it.`,
			action: (
				<Button
					size="small"
					onClick={() => void navigate(settingsHref)}
				>
					See DNS record
				</Button>
			)
		});
	}
	if (
		bucket.emailVerificationRequired &&
		summary &&
		!summary.mailDeliveryConfigured
	) {
		attention.push({
			key: 'mail',
			type: 'warning',
			title: `Email verification is required, but this server cannot send email. ${summary.unverified > 0 ? `${plural(summary.unverified, 'unverified user cannot', 'unverified users cannot')} sign in.` : 'Anyone who signs up will not be able to verify their address.'}`,
			action: can.editSettings ? (
				<Button
					size="small"
					onClick={onOpenSignIn}
				>
					Change sign-in
				</Button>
			) : null
		});
	}
	if (bucket.totpRequired && !bucket.passwordLogin) {
		attention.push({
			key: 'totp',
			type: 'info',
			title:
				'An authenticator app is required, but password sign-in is off, so the requirement does nothing.',
			action: can.editSettings ? (
				<Button
					size="small"
					onClick={onOpenSignIn}
				>
					Change sign-in
				</Button>
			) : null
		});
	}
	if (superAdmin && bucket.ownerTeamId === UNASSIGNED_GROUP_ID && !special) {
		attention.push({
			key: 'system',
			type: 'info',
			title:
				'This project belongs to the System team, so no customer team manages it.',
			action: (
				<Button
					size="small"
					onClick={() => void navigate(settingsHref)}
				>
					Move to team…
				</Button>
			)
		});
	}
	if (!special && applications === 0) {
		attention.push({
			key: 'unused',
			type: 'info',
			title: 'No application signs in here yet.',
			action: (
				<Button
					size="small"
					onClick={() => void navigate(bucketHref(bucket._id, 'applications'))}
				>
					Open Applications
				</Button>
			)
		});
	}
	if (bucket.addressForm === 'unaddressed') {
		attention.push({
			key: 'address',
			type: 'warning',
			title:
				'This project has no address of its own, so no application can sign in to it.',
			action: (
				<Button
					size="small"
					onClick={() => void navigate(settingsHref)}
				>
					Open Settings
				</Button>
			)
		});
	}

	const copyable = (value: string | null | undefined) =>
		value ? (
			<Typography.Text
				code
				copyable
			>
				{value}
			</Typography.Text>
		) : (
			<Typography.Text type="secondary">None</Typography.Text>
		);

	const verification = bucket.emailVerificationRequired
		? `Required · ${bucket.verificationMethod === 'code' ? 'code' : 'link'}`
		: 'Not required';

	const numbers: { title: string; value: number; href: string }[] = summary
		? [
				{
					title: 'Users',
					value: summary.users,
					href: bucketHref(bucket._id, 'users')
				},
				{
					title: 'Groups',
					value: summary.groups,
					href: bucketHref(bucket._id, 'groups')
				},
				{
					title: 'Provisioning connections',
					value: summary.connections,
					href: bucketHref(bucket._id, 'provisioning')
				},
				...(summary.activeThisMonth !== undefined && can.readActivity
					? [
							{
								title: 'Active this month',
								value: summary.activeThisMonth,
								href: bucketHref(bucket._id, 'activity')
							}
						]
					: [])
			]
		: [];

	return (
		<Flex
			vertical
			gap={16}
		>
			{attention.map((item) => (
				<Alert
					key={item.key}
					type={item.type}
					showIcon
					title={item.title}
					action={item.action}
				/>
			))}

			<Row gutter={[16, 16]}>
				<Col
					xs={24}
					lg={14}
				>
					<Card title="Connection details">
						<Descriptions
							column={1}
							size="small"
							items={[
								{
									key: 'issuer',
									label: 'Issuer URL',
									children: copyable(bucket.issuer)
								},
								{
									key: 'discovery',
									label: 'Discovery URL',
									children: copyable(bucket.discoveryUrl)
								},
								{
									key: 'form',
									label: 'Address',
									children: bucket.addressForm
										? ADDRESS_FORM[bucket.addressForm]
										: '—'
								},
								{ key: 'team', label: 'Owning team', children: groupName },
								{
									key: 'holds',
									label: 'Holds',
									children: (
										<Flex
											wrap
											gap={8}
											align="center"
										>
											<Link href={bucketHref(bucket._id, 'applications')}>
												{plural(applications, 'application', 'applications')}
											</Link>
											<Link href={bucketHref(bucket._id, 'apis')}>
												{plural(apis, 'API', 'APIs')}
											</Link>
										</Flex>
									)
								},
								{
									key: 'created',
									label: 'Created',
									children: new Date(bucket.createdAt).toLocaleDateString()
								}
							]}
						/>
					</Card>
				</Col>
				<Col
					xs={24}
					lg={10}
				>
					<Card
						title="Sign-in at a glance"
						extra={
							can.editSettings ? (
								<Button
									type="link"
									onClick={onOpenSignIn}
								>
									Change
								</Button>
							) : null
						}
					>
						<Descriptions
							column={1}
							size="small"
							items={[
								{
									key: 'password',
									label: 'Password sign-in',
									children: bucket.passwordLogin ? 'On' : 'Off'
								},
								{
									key: 'totp',
									label: 'Second factor',
									children: bucket.totpRequired
										? 'Required for password sign-in'
										: 'Not required'
								},
								{
									key: 'signup',
									label: 'Self-service sign-up',
									children: bucket.registrationOpen ? 'Open' : 'Closed'
								},
								{
									key: 'verification',
									label: 'Email verification',
									children: verification
								},
								{
									key: 'providers',
									label: 'Identity providers',
									children: summary
										? `${String(summary.providers.enabled)} enabled, ${String(summary.providers.creating)} create accounts`
										: '—'
								}
							]}
						/>
					</Card>
				</Col>
			</Row>

			{summary?.plan && (
				<BucketPlanCard
					bucketId={bucket._id}
					bucketName={bucket.name}
					plan={summary.plan}
					canSetPlan={can.setPlan}
					onChanged={onChanged}
				/>
			)}

			{summaryFailed && (
				<Alert
					type="warning"
					showIcon
					title="The project's numbers could not be read. Reload to try again."
				/>
			)}
			{numbers.length > 0 && (
				<Row gutter={[16, 16]}>
					{numbers.map((n) => (
						<Col
							key={n.title}
							xs={12}
							md={6}
						>
							<Card size="small">
								<Link href={n.href}>
									<Statistic
										title={n.title}
										value={n.value}
									/>
								</Link>
							</Card>
						</Col>
					))}
				</Row>
			)}

			{(can.edit || superAdmin) && (
				<RecentChanges
					title="Recent changes"
					params={{ project: bucket._id }}
					empty="No changes recorded for this project yet."
				/>
			)}
		</Flex>
	);
}
