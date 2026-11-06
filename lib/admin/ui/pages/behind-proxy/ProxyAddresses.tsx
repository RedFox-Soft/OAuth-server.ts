import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, Flex, Segmented, Tag, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import {
	ADDRESSES_SUPPORTED,
	PROXY_KINDS,
	recipeFor,
	type ProxyKind
} from '../../../../behind_proxy/recipes.js';
import {
	addressesProven,
	PROXY_LABELS,
	whenText,
	type AddressesView
} from './appView.js';

/*
 * Step 5 of Connect (specs/124 FR-010): whether the operator's proxy passes people's addresses in a way a network
 * condition can believe. It shows only what the checks saw — flags, never the address — the project's proxy keys,
 * the recipe that sends one, and a probe: a forged address that must never reach the check.
 */

export const PROBE_ADDRESS = '192.0.2.66';

interface KeyView {
	id: string;
	createdAt: string;
}

function flagLines(last: NonNullable<AddressesView['last']>): string[] {
	const lines: string[] = [];
	lines.push(
		!last.keyPresent
			? 'No proxy key was sent.'
			: last.keyValid
				? 'The proxy key was accepted.'
				: "The proxy key is not one of this project's."
	);
	if (!last.addressPresent) lines.push('No address was sent.');
	else if (!last.single) lines.push('The address was not one plain address.');
	else if (last.probe)
		lines.push(
			`The probe address ${PROBE_ADDRESS} reached the check: your proxy passes on what a browser writes.`
		);
	else if (last.cloudflare)
		lines.push(
			"The address is one of Cloudflare's: your proxy sees the CDN, not the person."
		);
	else if (!last.isPublic)
		lines.push(
			'The address is a private one: your proxy probably sits behind a load balancer.'
		);
	else lines.push('A public address was sent.');
	return lines;
}

export function ProxyAddresses({
	bucketId,
	addresses,
	proxyKind,
	verifyUrl,
	address,
	target,
	onRefresh
}: {
	bucketId: string;
	addresses: AddressesView;
	proxyKind: ProxyKind;
	verifyUrl: string;
	/* The app's address, or the API's identifier. */
	address: string;
	target: 'app' | 'api';
	onRefresh: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [kind, setKind] = useState<ProxyKind>(proxyKind);
	const [keys, setKeys] = useState<KeyView[] | null>(null);
	const [shown, setShown] = useState<string | null>(null);
	const keysUrl = `/admin/api/projects/${encodeURIComponent(bucketId)}/proxy-keys`;

	const load = useCallback(() => {
		void request<{ keys: KeyView[] }>('GET', keysUrl).then((result) => {
			if (result.ok) setKeys(result.data.keys);
		});
	}, [keysUrl]);
	useEffect(load, [load]);

	async function issue() {
		const result = await request<{ key: string }>('POST', keysUrl, {});
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		setShown(result.data.key);
		load();
	}

	async function withdraw(key: KeyView) {
		const agreed = await confirm('bucket.proxyKey.withdraw', {
			target: whenText(key.createdAt),
			consequences: [
				'A proxy still sending this key no longer has addresses believed, so every network condition refuses its requests.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${keysUrl}/${encodeURIComponent(key.id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Proxy key withdrawn.');
		load();
	}

	const proven = addressesProven(addresses);
	const recipe = recipeFor(kind, {
		verifyUrl,
		appAddress: address,
		target,
		addresses: true
	});
	const probeUrl = target === 'app' ? `${address}/_foxauth/address` : address;
	const probe = `curl -H 'X-Forwarded-For: ${PROBE_ADDRESS}' ${probeUrl}`;

	return (
		<Card
			size="small"
			title="Your proxy passes people's addresses"
			extra={
				<Button
					size="small"
					icon={<ReloadOutlined />}
					onClick={onRefresh}
				>
					Check again
				</Button>
			}
		>
			<Flex
				vertical
				gap={12}
			>
				<Typography.Text type="secondary">
					Needed only for &quot;From where&quot; conditions. Your proxy writes
					the address its connection came from and shows a key of this project,
					so a browser cannot choose the address it is judged by.
				</Typography.Text>
				{!ADDRESSES_SUPPORTED[kind] && (
					<Alert
						type="warning"
						showIcon
						title={`Network conditions are not supported yet with ${PROXY_LABELS[kind]}.`}
						description="Its recipe has not yet been proven to keep a browser's address and the key apart from the app. Use Caddy or nginx in front of this one for now."
					/>
				)}
				<Flex
					gap={8}
					align="center"
				>
					{proven ? (
						<Tag color="success">Proven {whenText(addresses.provenAt)}</Tag>
					) : addresses.forgedAt &&
					  (!addresses.provenAt ||
							Date.parse(addresses.forgedAt) >=
								Date.parse(addresses.provenAt)) ? (
						<Tag color="error">
							A forged address got through {whenText(addresses.forgedAt)}
						</Tag>
					) : (
						<Tag>Not proven yet</Tag>
					)}
					<Typography.Text type="secondary">
						{proven
							? 'Network conditions can be saved.'
							: 'Network conditions cannot be saved until a check arrives with the key and a public address.'}
					</Typography.Text>
				</Flex>
				{addresses.last && (
					<Flex vertical>
						<Typography.Text strong>
							The last check, on this server
						</Typography.Text>
						{flagLines(addresses.last).map((line) => (
							<Typography.Text
								key={line}
								type="secondary"
							>
								{line}
							</Typography.Text>
						))}
					</Flex>
				)}

				<Typography.Text strong>
					1. A proxy key for this project
				</Typography.Text>
				{shown && (
					<Alert
						type="success"
						showIcon
						title="Copy this key now. It is not shown again."
						description={
							<Typography.Text
								code
								copyable={{ text: shown }}
							>
								{shown}
							</Typography.Text>
						}
					/>
				)}
				{(keys ?? []).map((key) => (
					<Flex
						key={key.id}
						gap={8}
						align="center"
					>
						<Typography.Text>Issued {whenText(key.createdAt)}</Typography.Text>
						<Button
							size="small"
							danger
							onClick={() => void withdraw(key)}
						>
							Withdraw
						</Button>
					</Flex>
				))}
				<Button
					style={{ alignSelf: 'flex-start' }}
					disabled={(keys ?? []).length >= 2}
					onClick={() => void issue()}
				>
					Issue a proxy key
				</Button>
				<Typography.Text type="secondary">
					A project has at most two, so a new one can replace the old without a
					moment when your proxy is refused.
				</Typography.Text>

				<Typography.Text strong>
					2. The configuration that sends it
				</Typography.Text>
				<Segmented<ProxyKind>
					value={kind}
					onChange={setKind}
					options={PROXY_KINDS.map((k) => ({
						value: k,
						label: PROXY_LABELS[k]
					}))}
				/>
				<Typography.Text type="secondary">
					{kind === 'caddy'
						? 'Set FOXAUTH_PROXY_KEY in the environment Caddy runs in.'
						: 'Put the key where the configuration says <FOXAUTH_PROXY_KEY>.'}{' '}
					A CDN in front of your proxy is not supported, except Cloudflare when
					your proxy accepts connections only from Cloudflare.
				</Typography.Text>
				<pre
					style={{
						margin: 0,
						padding: 12,
						overflowX: 'auto',
						background: 'var(--ant-color-fill-quaternary, #f5f5f5)',
						borderRadius: 6,
						fontSize: 12
					}}
				>
					{recipe}
				</pre>

				<Typography.Text strong>
					3. Prove a browser cannot choose its address
				</Typography.Text>
				<Typography.Text type="secondary">
					Run this from any computer, then press Check again. The step must not
					turn red.
				</Typography.Text>
				<Typography.Text
					code
					copyable={{ text: probe }}
				>
					{probe}
				</Typography.Text>
				{target === 'app' && (
					<Typography.Text type="secondary">
						Or open{' '}
						<Typography.Link
							href={probeUrl}
							target="_blank"
						>
							{probeUrl}
						</Typography.Link>{' '}
						to see your own address as the check sees it.
					</Typography.Text>
				)}
			</Flex>
		</Card>
	);
}
