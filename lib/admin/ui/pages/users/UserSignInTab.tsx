import { useState } from 'react';
import { Button, Card, Flex, Tag, Typography } from 'antd';
import type { BucketCan } from '../../frame/can.js';
import { SetPasswordModal } from '../../accounts/SetPasswordModal.js';
import type { BucketView } from '../bucketView.js';
import { UserIdentityLinks } from '../UserIdentities.js';
import { usersApi, type EndUser } from './endUser.js';
import { useUserActions } from './useUserActions.js';
import { SessionsCard } from './SessionsCard.js';

/* What can be said about their password. Older accounts carry no marker, and then nothing is claimed. */
function passwordText(user: EndUser): string | null {
	if (user.passwordSet === undefined) return null;
	if (user.passwordSet) return 'Set.';
	return 'Not set — they sign in through an identity provider, or not at all until one is set.';
}

export function UserSignInTab({
	bucketId,
	bucket,
	user,
	can,
	onChanged
}: {
	bucketId: string;
	bucket: BucketView;
	user: EndUser;
	can: BucketCan;
	onChanged: () => void;
}) {
	const actions = useUserActions(bucketId);
	const [pwOpen, setPwOpen] = useState(false);
	const local = !user.provisionedBy;
	const passwordLogin = bucket.passwordLogin;
	const said = passwordText(user);

	return (
		<Flex
			vertical
			gap={16}
		>
			<Card
				title="Password"
				extra={
					can.manageUsers && local ? (
						<Button onClick={() => setPwOpen(true)}>Set password…</Button>
					) : undefined
				}
			>
				<Flex
					vertical
					gap={4}
				>
					{said && <Typography.Text>{said}</Typography.Text>}
					{!passwordLogin && (
						<Typography.Text type="secondary">
							This bucket does not accept password sign-in: a password, if set,
							is not used.
						</Typography.Text>
					)}
					{!local && (
						<Typography.Text type="secondary">
							The directory that manages them sets their password.
						</Typography.Text>
					)}
					{!said && passwordLogin && local && (
						<Typography.Text type="secondary">
							Whether a password was ever set is not recorded for accounts this
							old. Setting one now makes it known.
						</Typography.Text>
					)}
				</Flex>
			</Card>

			<Card
				title="Authenticator"
				extra={
					can.manageUsers && user.totpEnrolled ? (
						<Button
							danger
							onClick={() =>
								void actions.resetTotp(user).then((done) => {
									if (done) onChanged();
								})
							}
						>
							Reset authenticator
						</Button>
					) : undefined
				}
			>
				<Flex
					vertical
					gap={4}
				>
					<Typography.Text>
						{user.totpEnrolled ? (
							<>
								<Tag color="green">Set up</Tag>
								{user.totpEnrolledAt
									? `on ${new Date(user.totpEnrolledAt).toLocaleString()}`
									: null}
							</>
						) : (
							'Not set up.'
						)}
					</Typography.Text>
					<Typography.Text type="secondary">
						{bucket.totpRequired
							? 'This bucket requires one for password sign-in; without one, they set it up at their next sign-in.'
							: 'This bucket does not require one.'}
					</Typography.Text>
				</Flex>
			</Card>

			<Card title="Identity links">
				<UserIdentityLinks
					bucketId={bucketId}
					user={user}
					canRemove={can.manageUsers}
					passwordUsable={passwordLogin && user.passwordSet !== false}
					onChanged={onChanged}
				/>
			</Card>

			<SessionsCard
				bucketId={bucketId}
				user={user}
				canManage={can.manageUsers}
				refreshKey={user}
			/>

			<SetPasswordModal
				account={pwOpen ? user : null}
				url={`${usersApi(bucketId, user._id)}/password`}
				onClose={() => setPwOpen(false)}
				onDone={onChanged}
			/>
		</Flex>
	);
}
