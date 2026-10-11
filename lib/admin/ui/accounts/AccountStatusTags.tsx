import { Tag, Tooltip } from 'antd';

/*
 * Only what is out of the ordinary about an account (specs/082): an active, verified account carries no
 * tag at all, so the ones that do stand out in a long list. Shared by end users and, in phase 4, by
 * administrators, whose accounts have the same states.
 */
export function AccountStatusTags({
	account,
	showUnverified = true
}: {
	account: {
		active: boolean;
		verified: boolean;
		lockedLocally?: { at: string; reason: string } | null;
	};
	showUnverified?: boolean;
}) {
	return (
		<>
			{!account.active && <Tag>Deactivated</Tag>}
			{account.lockedLocally && (
				<Tooltip
					title={`Locked ${new Date(account.lockedLocally.at).toLocaleString()}: ${account.lockedLocally.reason}`}
				>
					<Tag color="red">Locked</Tag>
				</Tooltip>
			)}
			{showUnverified && !account.verified && (
				<Tag color="orange">Unverified</Tag>
			)}
		</>
	);
}
