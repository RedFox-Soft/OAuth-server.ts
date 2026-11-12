import { useCallback, useEffect, useState } from 'react';
import { Alert, Tag, Tooltip } from 'antd';
import { request } from '../../frame/request.js';

interface Vouching {
	status: 'vouched' | 'not_vouched' | 'not_checked';
	step?: 'challenge' | 'path_inserted' | 'root';
	reason?: string;
	expectedIssuer: string;
	/* The project serves the metadata itself, for an API its proxy checks (specs/123 R5): nothing was fetched. */
	servedByProject?: boolean;
}

const STEP_LABEL: Record<NonNullable<Vouching['step']>, string> = {
	challenge: 'the 401 challenge',
	path_inserted: 'the path-inserted well-known address',
	root: 'the root well-known address'
};

const REASON_LABEL: Record<string, string> = {
	unreachable: 'the resource could not be reached',
	blocked_address:
		'the resource is on a private address this server does not fetch',
	not_https: 'the resource is not served over https',
	no_metadata: 'no protected resource metadata was found',
	resource_mismatch: 'the metadata describes a different resource',
	issuer_not_listed: 'the metadata does not list this server',
	malformed: 'the metadata is not valid JSON'
};

/*
 * Whether the resource's own metadata vouches for this declaration. Informational, since nothing is refused on it:
 * it answers why an MCP client might not find this server.
 */
function useVouching(url: string): {
	vouching: Vouching | null;
	checking: boolean;
} {
	const [vouching, setVouching] = useState<Vouching | null>(null);
	const [checking, setChecking] = useState(true);
	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchVouching = useCallback(
		() =>
			request<Vouching>('GET', url).then((result) => {
				setVouching(result.ok ? result.data : null);
				setChecking(false);
			}),
		[url]
	);
	useEffect(() => {
		void fetchVouching();
	}, [fetchVouching]);
	return { vouching, checking };
}

function detailOf(vouching: Vouching): string {
	return vouching.status === 'vouched'
		? `Found through ${STEP_LABEL[vouching.step ?? 'path_inserted']}.`
		: `${REASON_LABEL[vouching.reason ?? ''] ?? 'Metadata not found'}. It must list ${vouching.expectedIssuer} in authorization_servers.`;
}

/* The reasons read as clauses in the list's tooltip; standing alone they start a sentence. */
function sentence(text: string): string {
	return text.charAt(0).toUpperCase() + text.slice(1);
}

/* Fetched per row once the list is on screen, so a slow resource delays its own cell and nothing else. */
export function VouchingCell({ url }: { url: string }) {
	const { vouching, checking } = useVouching(url);
	if (checking) return <Tag>checking…</Tag>;
	if (!vouching) return <Tag>unavailable</Tag>;
	if (vouching.servedByProject) {
		return (
			<Tooltip
				title={`Your proxy checks this API's tokens, and this project serves its metadata, naming ${vouching.expectedIssuer}.`}
			>
				<Tag color="green">Served by the project</Tag>
			</Tooltip>
		);
	}
	const color =
		vouching.status === 'vouched'
			? 'green'
			: vouching.status === 'not_checked'
				? 'default'
				: 'orange';
	const label =
		vouching.status === 'vouched'
			? 'found'
			: vouching.status === 'not_checked'
				? 'not checked'
				: 'not found';
	return (
		<Tooltip title={detailOf(vouching)}>
			<Tag color={color}>{label}</Tag>
		</Tooltip>
	);
}

/* The same answer on the API's Connect tab, spelled out rather than behind a tooltip. */
export function VouchingStatus({ url }: { url: string }) {
	const { vouching, checking } = useVouching(url);
	if (checking) {
		return (
			<Alert
				type="info"
				showIcon
				title="Checking your API's metadata…"
			/>
		);
	}
	if (!vouching) {
		return (
			<Alert
				type="warning"
				showIcon
				title="Your API's metadata could not be checked just now"
			/>
		);
	}
	if (vouching.status === 'vouched') {
		return (
			<Alert
				type="success"
				showIcon
				title="Your API's metadata names this server"
				description={detailOf(vouching)}
			/>
		);
	}
	return (
		<Alert
			type={vouching.status === 'not_checked' ? 'info' : 'warning'}
			showIcon
			title={
				vouching.status === 'not_checked'
					? "Your API's metadata was not checked"
					: "Your API's metadata was not found"
			}
			description={`${sentence(detailOf(vouching))} Without it, an MCP client cannot find where to sign in.`}
		/>
	);
}
