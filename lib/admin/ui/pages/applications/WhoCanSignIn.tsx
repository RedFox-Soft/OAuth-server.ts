import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, Flex, Tooltip, Typography } from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { bucketCan } from '../../frame/can.js';
import { useMe } from '../../frame/me.js';
import { bucketHref } from '../../frame/routes.js';
import { Link } from '../../frame/router.js';
import type { BucketSummary, BucketView } from '../bucketView.js';
import { useSignInSave } from '../signin/useSignInSave.js';

function people(n: number): string {
	return `${n.toLocaleString('en-US')} ${n === 1 ? 'person' : 'people'}`;
}

/*
 * Who can sign in to the project an application signs people into (spec 107). A new project is closed to sign-ups
 * and holds nobody (specs/083), so a developer who has just wired an app up would meet a sign-in page with no way
 * through. This says so at that moment and offers the two ways in, each through the route and the confirmation the
 * rest of the console uses for it.
 */
export function WhoCanSignIn({
	bucket,
	onBucketChanged
}: {
	bucket: BucketView;
	onBucketChanged: () => void;
}) {
	const feedback = useFeedback();
	const { me } = useMe();
	const can = bucketCan(bucket);
	const save = useSignInSave(bucket._id, bucket.name);
	const [summary, setSummary] = useState<BucketSummary | null>(null);
	const [busy, setBusy] = useState<'invite' | 'open' | null>(null);
	const [refusal, setRefusal] = useState<string | null>(null);

	const base = `/admin/api/projects/${encodeURIComponent(bucket._id)}`;
	const fetchSummary = useCallback(
		() =>
			request<BucketSummary>('GET', `${base}/summary`).then((result) => {
				if (result.ok) setSummary(result.data);
			}),
		[base]
	);
	useEffect(() => {
		void fetchSummary();
	}, [fetchSummary]);

	if (!summary) return null;

	const open = bucket.registrationOpen;
	const passwords = bucket.passwordLogin;
	const paused = summary.plan?.signUpsPaused === true;
	const nobody = summary.users === 0 && !open;

	async function invite() {
		if (!me) return;
		setBusy('invite');
		setRefusal(null);
		try {
			const result = await request<{ invitation?: 'sent' | 'failed' }>(
				'POST',
				`${base}/users`,
				{ email: me.email, invite: true }
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			if (result.data.invitation === 'failed') {
				setRefusal(
					`The account was created, but the invitation to ${me.email} could not be sent. Resend it from the person's page once mail works.`
				);
			} else {
				feedback.done(`Invitation sent to ${me.email}.`);
			}
			await fetchSummary();
		} finally {
			setBusy(null);
		}
	}

	async function openSignUps() {
		setBusy('open');
		setRefusal(null);
		try {
			const outcome = await save({ registrationOpen: true });
			if (outcome.kind === 'refused') setRefusal(outcome.message);
			if (outcome.kind === 'saved') onBucketChanged();
		} finally {
			setBusy(null);
		}
	}

	const inviteBlocked = !summary.mailDeliveryConfigured
		? 'Mail is not configured on this instance, so an invitation cannot be sent.'
		: !passwords
			? 'Password sign-in is off in this project; an invitation sets a password.'
			: null;

	return (
		<Card
			size="small"
			title="Who can sign in"
		>
			<Flex
				vertical
				gap={8}
			>
				{nobody ? (
					<Typography.Text>
						Nobody can sign in yet: this project has no people and does not take
						sign-ups.
					</Typography.Text>
				) : (
					<Typography.Text>
						{people(summary.users)}
						{' · '}
						{open
							? paused
								? 'sign-ups paused by the plan'
								: 'anyone can create an account'
							: 'no self-service sign-up'}
					</Typography.Text>
				)}
				{nobody && (
					<Flex
						gap={8}
						wrap
					>
						{can.manageUsers && (
							<Tooltip title={inviteBlocked ?? undefined}>
								<Button
									type="primary"
									loading={busy === 'invite'}
									disabled={inviteBlocked !== null || !me}
									onClick={() => void invite()}
								>
									Add a test user
								</Button>
							</Tooltip>
						)}
						{can.editSettings && (
							<Button
								loading={busy === 'open'}
								disabled={!passwords}
								onClick={() => void openSignUps()}
							>
								Open sign-ups
							</Button>
						)}
					</Flex>
				)}
				{nobody && me && can.manageUsers && (
					<Typography.Text type="secondary">
						The test user is you: an invitation to {me.email} to set a password
						in this project.
					</Typography.Text>
				)}
				{refusal && (
					<Alert
						type="warning"
						showIcon
						title={refusal}
					/>
				)}
				<Link href={bucketHref(bucket._id, 'sign-in')}>
					All sign-in settings
				</Link>
			</Flex>
		</Card>
	);
}
