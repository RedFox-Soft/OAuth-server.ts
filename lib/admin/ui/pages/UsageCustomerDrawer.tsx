import { Descriptions, Drawer, Space, Table, Tag, Typography } from 'antd';
import {
	changeText,
	figureText,
	type CustomerSummary,
	type OverviewRow
} from '../activity/model.js';
import { Link } from '../frame/router.js';
import { bucketHref, groupHref, usageBucketHref } from '../frame/routes.js';

/*
 * One customer of the usage dashboard (specs/077): who it is, whom to talk to, and its buckets. A customer
 * is a group; the drawer reads it from the overview answer rather than the group routes, which a super
 * administrator's System scope would answer differently.
 */
export function UsageCustomerDrawer({
	summary,
	rows,
	month,
	previous,
	onClose
}: {
	summary: CustomerSummary | null;
	rows: readonly OverviewRow[];
	month: string;
	previous: string;
	onClose: () => void;
}) {
	const customer = summary?.customer ?? null;
	const held = rows.filter((row) =>
		summary ? summary.bucketIds.includes(row.bucketId) : false
	);
	const kindText =
		customer === null
			? ''
			: customer.kind === null
				? customer.groupId === null
					? 'not recorded'
					: 'deleted group'
				: customer.kind;

	return (
		<Drawer
			open={summary !== null}
			onClose={onClose}
			size="large"
			destroyOnHidden
			title={customer?.label ?? ''}
		>
			{summary && customer ? (
				<>
					<Descriptions
						column={1}
						size="small"
						items={[
							{
								key: 'kind',
								label: 'Group',
								// A live group opens its page (specs/086); a deleted or unrecorded one is only named.
								children:
									customer.exists && customer.groupId !== null ? (
										<Link href={groupHref(customer.groupId)}>{kindText}</Link>
									) : (
										kindText
									)
							},
							{
								key: 'contacts',
								label: 'Contacts (owners)',
								children:
									summary.contacts.length > 0 ? (
										<Space wrap>
											{summary.contacts.map((email) => (
												<Typography.Text
													key={email}
													copyable
												>
													{email}
												</Typography.Text>
											))}
										</Space>
									) : (
										'—'
									)
							},
							{
								key: 'members',
								label: 'Members',
								children: String(summary.memberCount)
							},
							{
								key: 'current',
								label: month,
								children: figureText(summary.current)
							},
							{
								key: 'previous',
								label: previous,
								children: figureText(summary.previous)
							}
						]}
					/>
					<Typography.Paragraph
						type="secondary"
						style={{ marginTop: 16 }}
					>
						A customer&apos;s figure is the sum of its buckets&apos; figures.
						Each bucket is its own population, so a person with accounts in two
						buckets is counted in both.
					</Typography.Paragraph>
					<Table
						size="small"
						rowKey="bucketId"
						pagination={false}
						dataSource={held}
						columns={[
							{
								title: 'Bucket',
								key: 'name',
								render: (_: unknown, row: OverviewRow) => (
									<>
										{row.deleted === null ? (
											<Link href={bucketHref(row.bucketId)}>{row.name}</Link>
										) : (
											<Link href={usageBucketHref(row.bucketId, month)}>
												{row.name}
											</Link>
										)}{' '}
										{row.deleted ? <Tag color="red">Deleted</Tag> : null}
									</>
								)
							},
							{
								title: month,
								key: 'current',
								render: (_: unknown, row: OverviewRow) =>
									figureText(row.months[0] ?? null)
							},
							{
								title: previous,
								key: 'previous',
								render: (_: unknown, row: OverviewRow) =>
									figureText(row.months[1] ?? null)
							},
							{
								title: 'Change',
								key: 'change',
								render: (_: unknown, row: OverviewRow) =>
									changeText(row.months[0] ?? null, row.months[1] ?? null)
							}
						]}
					/>
				</>
			) : null}
		</Drawer>
	);
}
