import { useCallback, useEffect, useState } from 'react';
import { Drawer, Flex, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { dateWords } from './users/UserActivityTab.js';

interface OwnRow {
	at: string;
	outcome: 'let_in' | 'refused';
	place: string;
	method: string | null;
	reason: string | null;
	device: string | null;
	country: string | null;
}

type OwnView =
	| { state: 'off' }
	| { state: 'empty'; since: string }
	| { state: 'list'; rows: OwnRow[] };

function countryName(code: string): string {
	try {
		return (
			new Intl.DisplayNames(undefined, { type: 'region' }).of(code) ?? code
		);
	} catch {
		return code;
	}
}

function whenWords(at: string): string {
	return new Date(at).toLocaleString(undefined, {
		dateStyle: 'medium',
		timeStyle: 'short'
	});
}

/*
 * The administrator's own last sign-ins (specs/137 contracts/console.md), opened from their email in the header. No
 * address on purpose (SI-3): whoever holds this session may not be the administrator, and a colleague who is can ask
 * a super administrator for the full record.
 */
export function OwnSignInsDrawer({
	open,
	onClose
}: {
	open: boolean;
	onClose: () => void;
}) {
	return (
		<Drawer
			title="Your recent sign-ins"
			open={open}
			onClose={onClose}
			size="large"
			destroyOnHidden
		>
			{open && <OwnSignInsList />}
			<Typography.Paragraph
				type="secondary"
				style={{ marginTop: 16 }}
			>
				Something you don&apos;t recognise? Ask a super administrator to look at
				your sign-ins and sign you out everywhere.
			</Typography.Paragraph>
		</Drawer>
	);
}

/* Mounted each time the drawer opens, so every opening reads afresh. */
export function OwnSignInsList() {
	const [view, setView] = useState<OwnView | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);

	// Every state write follows an await, as in Accounts, so the mount effect calls this as it is.
	const load = useCallback(async () => {
		try {
			const result = await request<OwnView>('GET', '/admin/api/me/sign-ins');
			if (!result.ok) {
				setError(result.error.message);
				return;
			}
			setError(null);
			setView(result.data);
		} finally {
			setLoading(false);
		}
	}, []);
	useEffect(() => {
		void load();
	}, [load]);

	if (error !== null) {
		return (
			<LoadFailed
				reason={error}
				onRetry={() => {
					setLoading(true);
					void load();
				}}
			/>
		);
	}
	if (loading || view === null) return null;
	if (view.state === 'off') {
		return <EmptyState purpose="Sign-ins aren't recorded on this server." />;
	}
	if (view.state === 'empty') {
		return (
			<EmptyState
				purpose={`No sign-ins since recording began on ${dateWords(view.since)}.`}
			/>
		);
	}
	return (
		<Flex
			vertical
			gap={4}
		>
			{view.rows.map((row) => (
				<Flex
					key={`${row.at}-${row.outcome}`}
					wrap
					gap={8}
					align="baseline"
					style={{
						padding: '8px 0',
						borderBottom: '1px solid rgba(5, 5, 5, 0.06)'
					}}
				>
					<Typography.Text type="secondary">
						{whenWords(row.at)}
					</Typography.Text>
					{row.outcome === 'refused' && <Tag color="red">Refused</Tag>}
					<Typography.Text strong>{row.place}</Typography.Text>
					<Typography.Text>
						{row.outcome === 'refused' ? row.reason : row.method}
					</Typography.Text>
					{row.device && (
						<Typography.Text type="secondary">{row.device}</Typography.Text>
					)}
					{row.country && (
						<Typography.Text type="secondary">
							{countryName(row.country)}
						</Typography.Text>
					)}
				</Flex>
			))}
		</Flex>
	);
}
