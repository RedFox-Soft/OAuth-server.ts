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
import { bucketHref, connectionHref, projectHref } from '../frame/routes.js';
import { request } from '../frame/request.js';
import type { BucketCan } from '../frame/can.js';
import { UNASSIGNED_GROUP_ID, reservedOf } from '../../consts.js';
import type { BucketSummary, BucketView } from './bucketView.js';

/*
 * A bucket's landing page (specs/081): what needs attention, how to connect an application to it, how people
 * sign in, and how many there are. It reads what the bucket read and the summary already say and edits
 * nothing — every change is one click away on the tab that owns it, so there is never a second editor.
 */

const ADDRESS_FORM: Record<NonNullable<BucketView['addressForm']>, string> = {
	root: "Served at the server's root",
	path: 'A path of the server',
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
	onOpenSignIn
}: {
	bucket: BucketView;
	summary: BucketSummary | null;
	summaryFailed: boolean;
	can: BucketCan;
	superAdmin: boolean;
	groupName: string;
	onOpenSignIn: () => void;
}) {
	const navigate = useNavigate();
	const special = reservedOf(bucket._id);
	/*
	 * The held connection itself, so the item opens the page that can end the hold (specs/084 US6). Read only
	 * when the summary says one is held; the list it comes from is short.
	 */
	const [heldId, setHeldId] = useState<string | null>(null);
	const anyHeld = summary !== null && summary.held > 0;
	useEffect(() => {
		if (!anyHeld) return;
		let live = true;
		void request<{ id: string; hold?: unknown }[]>(
			'GET',
			`/admin/api/buckets/${encodeURIComponent(bucket._id)}/provisioning-connections`
		).then((r) => {
			if (live && r.ok) setHeldId(r.data.find((c) => c.hold)?.id ?? null);
		});
		return () => {
			live = false;
		};
	}, [anyHeld, bucket._id]);
	const settingsHref = bucketHref(bucket._id, 'settings');
	const projects = bucket.projects ?? [];

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
	if (bucket.address && !bucket.address.requestsArrived) {
		attention.push({
			key: 'host',
			type: 'warning',
			title: `No request has reached ${bucket.address.host} yet. Create the DNS record so applications can reach it.`,
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
	if (superAdmin && bucket.ownerGroupId === UNASSIGNED_GROUP_ID && !special) {
		attention.push({
			key: 'system',
			type: 'info',
			title:
				'This bucket belongs to the System group, so no customer group manages it.',
			action: (
				<Button
					size="small"
					onClick={() => void navigate(settingsHref)}
				>
					Move to group…
				</Button>
			)
		});
	}
	if (!special && projects.length === 0) {
		attention.push({
			key: 'unused',
			type: 'info',
			title: 'No project signs in here yet.',
			action: (
				<Button
					size="small"
					onClick={() => void navigate('/admin/projects')}
				>
					Open Projects
				</Button>
			)
		});
	}
	if (bucket.addressForm === 'unaddressed') {
		attention.push({
			key: 'address',
			type: 'warning',
			title:
				'This bucket has no address of its own, so no application can sign in to it.',
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
					title: 'User groups',
					value: summary.userGroups,
					href: bucketHref(bucket._id, 'user-groups')
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
								{ key: 'group', label: 'Owning group', children: groupName },
								{
									key: 'projects',
									label: 'Used by',
									children:
										projects.length === 0 ? (
											<Typography.Text type="secondary">
												No project
											</Typography.Text>
										) : (
											<Flex
												wrap
												gap={8}
											>
												{projects.map((p) => (
													<Link
														key={p.id}
														href={projectHref(p.id)}
													>
														{`${p.name} (${plural(p.clientCount, 'application', 'applications')})`}
													</Link>
												))}
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

			{summaryFailed && (
				<Alert
					type="warning"
					showIcon
					title="The bucket's numbers could not be read. Reload to try again."
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

			{can.edit && (
				<Typography.Text>
					Recent changes:{' '}
					<Link
						href={`/admin/audit?targetId=${encodeURIComponent(bucket._id)}`}
					>
						audit entries for this bucket
					</Link>
					{' · '}
					<Link
						href={`/admin/audit?targetScope=${encodeURIComponent(bucket._id)}`}
					>
						for its users and groups
					</Link>
				</Typography.Text>
			)}
		</Flex>
	);
}
