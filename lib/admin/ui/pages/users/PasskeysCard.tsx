import { Button, Card, Flex, Tag, Tooltip, Typography } from 'antd';
import {
	BROWSER_NAMES,
	SYSTEM_NAMES
} from '../../../../person_activity/sign_in_words.js';
import type {
	ActivityBrowser,
	ActivitySystem
} from '../../../../adapters/types.js';
import type { EndUser, PasskeysOfPerson, PasskeyView } from './endUser.js';
import type { UserActions } from './useUserActions.js';

const VIA: Record<PasskeyView['createdVia'], string> = {
	passkey: 'after a passkey sign-in',
	password_code: 'after a password and a code',
	password_mail: 'after a password and an emailed link',
	password: 'after a password alone'
};

const NOT_WORKING: Record<Exclude<PasskeyView['state'], 'works'>, string> = {
	old_address: "Doesn't work at this address",
	copied: 'Blocked: it looked copied',
	off: 'Passkeys are off'
};

const day = (iso: string) =>
	new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });

/* "{browser} on {system}" from the closed sets the passkey was made on, as the person's own page names it. */
function madeOn(passkey: PasskeyView): string {
	const browser =
		BROWSER_NAMES[passkey.createdOn.browser as ActivityBrowser] ??
		'Another browser';
	const system = SYSTEM_NAMES[passkey.createdOn.system as ActivitySystem];
	return system ? `${browser} on ${system}` : browser;
}

/*
 * A person's passkeys on their "Sign-in methods" tab (specs/140 contracts/console-and-mail.md): what each is, whether it
 * signs in here and why not, and for those who manage the project's people, revoking one or all of them.
 */
export function PasskeysCard({
	user,
	of,
	canManage,
	actions,
	onRevoked
}: {
	user: EndUser;
	of: PasskeysOfPerson;
	canManage: boolean;
	actions: UserActions;
	onRevoked: () => void;
}) {
	const after = (done: boolean) => {
		if (done) onRevoked();
	};
	return (
		<Card
			title="Passkeys"
			extra={
				canManage && of.passkeys.length > 0 ? (
					<Button
						danger
						onClick={() => void actions.revokeAllPasskeys(user, of).then(after)}
					>
						Revoke all…
					</Button>
				) : undefined
			}
		>
			{of.passkeys.length === 0 ? (
				<Typography.Text type="secondary">No passkeys.</Typography.Text>
			) : (
				<Flex
					vertical
					gap={12}
				>
					{of.passkeys.map((passkey) => (
						<Flex
							key={passkey.id}
							justify="space-between"
							align="start"
							gap={12}
							wrap
						>
							<Flex
								vertical
								gap={2}
								style={{ minWidth: 0 }}
							>
								<Typography.Text strong>
									{passkey.name ?? madeOn(passkey)}{' '}
									{passkey.state !== 'works' && (
										<Tag color={passkey.state === 'off' ? 'default' : 'red'}>
											{NOT_WORKING[passkey.state]}
										</Tag>
									)}
									{passkey.state === 'works' && !passkey.confirmed && (
										<Tooltip title="Works like their password until they confirm it">
											<Tag color="gold">Not confirmed</Tag>
										</Tooltip>
									)}
								</Typography.Text>
								<Typography.Text type="secondary">
									{passkey.synced ? 'Synced' : 'On one device'} · Created{' '}
									{day(passkey.createdAt)}, {VIA[passkey.createdVia]} ·{' '}
									{passkey.lastUsedAt
										? `Last used ${day(passkey.lastUsedAt)}`
										: 'Never used'}
								</Typography.Text>
							</Flex>
							{canManage && (
								<Button
									danger
									size="small"
									onClick={() =>
										void actions.revokePasskey(user, passkey, of).then(after)
									}
								>
									Revoke…
								</Button>
							)}
						</Flex>
					))}
				</Flex>
			)}
		</Card>
	);
}
