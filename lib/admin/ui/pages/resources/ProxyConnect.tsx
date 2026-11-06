import { useState } from 'react';
import { Alert, Button, Card, Flex, Segmented, Table, Typography } from 'antd';
import { useFeedback } from '../../frame/feedback.js';
import {
	API_IDENTITY_HEADERS,
	PROXY_KINDS,
	recipeFor,
	type ProxyKind
} from '../../../../behind_proxy/recipes.js';
import { PROXY_LABELS, type AddressesView } from '../behind-proxy/appView.js';
import { ProxyAddresses } from '../behind-proxy/ProxyAddresses.js';

/* Keyed by the shared list, so a header the check starts answering cannot go unexplained here. */
const RECEIVES: Readonly<
	Record<(typeof API_IDENTITY_HEADERS)[number], string>
> = {
	'X-Auth-Subject':
		"The token's subject (sub): the person it was issued for, or the client itself for a token issued to a client alone. Some clients get a per-client identifier rather than the account id.",
	'X-Auth-Client': 'The client the token was issued to (client_id).',
	'X-Auth-Scope': "The token's scopes, space-separated.",
	'X-Auth-Reason':
		'Why the request was let through: allowed, or preflight for a browser’s CORS preflight, which carries no token and leaves the other three empty.'
};

const AUTHORIZATION_ROW = {
	header: 'Authorization',
	meaning:
		'Passed on unchanged, for an API that checks the token again or exchanges it for a person’s tokens elsewhere.'
};

function Copyable({ value }: { value: string }) {
	return (
		<Typography.Text
			code
			copyable={{ text: value }}
			style={{ wordBreak: 'break-all' }}
		>
			{value}
		</Typography.Text>
	);
}

/*
 * Connect for an API whose tokens the operator's proxy checks (specs/123 FR-019, FR-020). The whole path in one
 * place: where the proxy asks, the configuration that makes it ask, and what the API gets back. The two limits of
 * this mode are stated here because this is where someone decides whether the mode is enough for them.
 */
export function ProxyConnect({
	bucketId,
	identifier,
	check,
	addresses,
	onRefresh
}: {
	bucketId: string;
	identifier: string;
	check: { verifyUrl: string; metadataUrl: string };
	addresses: AddressesView | undefined;
	onRefresh: () => void;
}) {
	const feedback = useFeedback();
	const [kind, setKind] = useState<ProxyKind>('caddy');
	const recipe = recipeFor(kind, {
		verifyUrl: check.verifyUrl,
		appAddress: identifier,
		target: 'api'
	});

	async function copy() {
		try {
			await navigator.clipboard.writeText(recipe);
			feedback.done(`${PROXY_LABELS[kind]} configuration copied.`);
		} catch {
			feedback.refused({
				error: 'clipboard',
				message: 'The browser did not allow copying; select the text instead.'
			});
		}
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			<Alert
				type="warning"
				showIcon
				title="Anyone who can sign in to this project can get a token for this API."
				description="To limit who may call it — some groups, an attribute, a network, some hours — and which tools a token may call, use Access…"
			/>

			<Flex
				vertical
				gap={4}
			>
				<Typography.Text strong>Check address</Typography.Text>
				<Copyable value={check.verifyUrl} />
				<Typography.Text type="secondary">
					Your proxy calls it before each request and passes the request on only
					when it answers 200.
				</Typography.Text>
			</Flex>
			<Flex
				vertical
				gap={4}
			>
				<Typography.Text strong>Metadata address</Typography.Text>
				<Copyable value={check.metadataUrl} />
				<Typography.Text type="secondary">
					This project serves the API’s protected resource metadata here, and
					every refusal points clients to it. Your API serves nothing for it.
				</Typography.Text>
			</Flex>

			<Card
				size="small"
				title="Your proxy's configuration"
				extra={
					<Button
						size="small"
						onClick={() => void copy()}
					>
						Copy
					</Button>
				}
			>
				<Flex
					vertical
					gap={12}
				>
					<Segmented<ProxyKind>
						value={kind}
						onChange={setKind}
						options={PROXY_KINDS.map((k) => ({
							value: k,
							label: PROXY_LABELS[k]
						}))}
					/>
					<Typography.Text type="secondary">
						Replace the API's own address (http://127.0.0.1:8080) with where it
						listens.
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
				</Flex>
			</Card>

			<Card
				size="small"
				title="What your API receives"
			>
				<Flex
					vertical
					gap={12}
				>
					<Alert
						type="info"
						showIcon
						title="Make sure the API can be reached only through your proxy."
						description="Anyone who reaches it directly can send these headers themselves. The configuration above removes them from every request before asking this project."
					/>
					<Table
						size="small"
						pagination={false}
						rowKey="header"
						dataSource={[
							...API_IDENTITY_HEADERS.map((header) => ({
								header,
								meaning: RECEIVES[header]
							})),
							AUTHORIZATION_ROW
						]}
						columns={[
							{
								title: 'Header',
								dataIndex: 'header',
								render: (header: string) => (
									<Typography.Text
										code
										style={{ whiteSpace: 'nowrap' }}
									>
										{header}
									</Typography.Text>
								)
							},
							{ title: 'What it holds', dataIndex: 'meaning' }
						]}
					/>
				</Flex>
			</Card>

			{/* Research R9: the check does not guess the API's CORS policy, so the proxy has to supply it. */}
			<Alert
				type="info"
				showIcon
				title="Clients that run in a browser"
				description="Refusals from the check carry no CORS headers, so a browser-based client on another origin cannot read why it was refused. If you have such clients, have your proxy add CORS headers to error responses too. Preflight requests are let through without a token."
			/>
			{addresses && (
				<ProxyAddresses
					bucketId={bucketId}
					addresses={addresses}
					proxyKind="caddy"
					verifyUrl={check.verifyUrl}
					address={identifier}
					target="api"
					onRefresh={onRefresh}
				/>
			)}
		</Flex>
	);
}
