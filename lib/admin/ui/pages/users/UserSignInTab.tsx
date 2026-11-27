import { useEffect, useState } from 'react';
import { Button, Card, Flex, Tag, Typography } from 'antd';
import type { BucketCan } from '../../frame/can.js';
import { SetPasswordModal } from '../../accounts/SetPasswordModal.js';
import type { BucketView } from '../bucketView.js';
import { UserIdentityLinks } from '../UserIdentities.js';
import { request } from '../../frame/request.js';
import { ADMIN_BUCKET_ID } from '../../../consts.js';
import { usersApi, type EndUser, type PasskeysOfPerson } from './endUser.js';
import { PasskeysCard } from './PasskeysCard.js';
import { useUserActions } from './useUserActions.js';
import { SessionsCard } from './SessionsCard.js';
import { ConnectedAccountsCard } from './ConnectedAccountsCard.js';

/*
 * What can be said about their password. Older accounts carry no marker, and then nothing is claimed. Someone holding
 * a passkey that signs in here signs in with it, not "through an identity provider, or not at all" (specs/140 FR-004).
 */
function passwordText(user: EndUser, withPasskey: boolean): string | null {
	if (user.passwordSet === undefined) return null;
	if (user.passwordSet) return 'Set.';
	if (withPasskey) return 'Not set — they sign in with a passkey.';
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
	const [passkeys, setPasskeys] = useState<PasskeysOfPerson | null>(null);
	const [tick, setTick] = useState(0);
	const consoleBucket = bucketId === ADMIN_BUCKET_ID;
	const passkeysApi = `${usersApi(bucketId, user._id)}/passkeys`;

	// Read again whenever the page reloads the person, and after this card's own revocation.
	useEffect(() => {
		if (consoleBucket) return;
		let current = true;
		void request<PasskeysOfPerson>('GET', passkeysApi).then((result) => {
			if (current && result.ok) setPasskeys(result.data);
		});
		return () => {
			current = false;
		};
	}, [passkeysApi, consoleBucket, user, tick]);

	const local = !user.provisionedBy;
	const passwordLogin = bucket.passwordLogin;
	const withPasskey =
		passkeys?.passkeys.some((passkey) => passkey.state === 'works') ?? false;
	const said = passwordText(user, withPasskey);
	const providerOnly = user.passwordSet === false;
	const showPasskeys =
		!consoleBucket &&
		passkeys !== null &&
		(bucket.passkeyLogin === true || passkeys.passkeys.length > 0);
	/* What the person can do about an authenticator in this project's state (specs/126 contracts/administration.md). */
	const authenticatorState = user.totpEnrolled
		? 'They type a code at every password sign-in.'
		: providerOnly && withPasskey
			? "They sign in with a passkey, which already checks their fingerprint, face or PIN; an authenticator app isn't needed."
			: providerOnly
				? 'They sign in through a provider; an authenticator app is not used for them, and apps that require a code turn them away.'
				: bucket.totpRequired
					? `This project requires one: they set it up at their next password sign-in${user.totpProofRequired ? ', after a link we email them' : ''}.`
					: bucket.totpSelfService !== false
						? 'They can turn it on themselves on their account page, under Sign-in and security.'
						: 'This project does not let people set one up themselves, so they cannot get one now.';

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
							This project does not accept password sign-in: a password, if set,
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

			{showPasskeys && (
				<PasskeysCard
					user={user}
					of={passkeys}
					canManage={can.manageUsers}
					passkeysEnabled={bucket.passkeyLogin === true}
					actions={actions}
					onRevoked={() => {
						setTick((n) => n + 1);
						onChanged();
					}}
				/>
			)}

			<Card
				title="Authenticator app"
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
							Remove authenticator app…
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
									? ` on ${new Date(user.totpEnrolledAt).toLocaleString()}`
									: null}
								{user.totpEnrolledVia === 'self'
									? ', by them on their account page.'
									: ', at sign-in, while the project required one.'}
							</>
						) : (
							'Not set up.'
						)}
					</Typography.Text>
					<Typography.Text type="secondary">
						{authenticatorState}
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

			<ConnectedAccountsCard
				bucketId={bucketId}
				userId={user._id}
				canDisconnect={can.manageUsers}
			/>

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
