import { Flex, Space, Typography } from 'antd';
import { ProxyConnect } from './ProxyConnect.js';
import { VouchingStatus } from './vouching.js';
import {
	resourcesApi,
	type ResourceConnection,
	type ResourceView
} from './resourceView.js';

/*
 * What a developer protecting this API must serve and check (spec 107): the values this server's tokens for it carry,
 * the metadata document an agent host looks for, and the challenge that sends it there — each to copy as it is.
 */
function ResourceConnectionDetails({
	connection
}: {
	connection: ResourceConnection;
}) {
	const copyable = (value: string) => (
		<Typography.Text
			code
			copyable={{ text: value }}
		>
			{value}
		</Typography.Text>
	);
	return (
		<Space
			orientation="vertical"
			size={12}
			style={{ width: '100%' }}
		>
			<div>
				<Typography.Text strong>Issuer</Typography.Text>
				<div>{copyable(connection.issuer)}</div>
			</div>
			<div>
				<Typography.Text strong>Audience (aud) of its tokens</Typography.Text>
				<div>{copyable(connection.audience)}</div>
			</div>
			{connection.metadataUrl && (
				<div>
					<Typography.Text strong>
						Serve this protected resource metadata at
					</Typography.Text>
					<div>{copyable(connection.metadataUrl)}</div>
					<Typography.Paragraph
						copyable={{ text: JSON.stringify(connection.metadata, null, 2) }}
					>
						<pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
							{JSON.stringify(connection.metadata, null, 2)}
						</pre>
					</Typography.Paragraph>
				</div>
			)}
			{connection.challenge && (
				<div>
					<Typography.Text strong>
						Answer a request without a valid token with 401 and
					</Typography.Text>
					<div>{copyable(`WWW-Authenticate: ${connection.challenge}`)}</div>
				</div>
			)}
			<div>
				<Typography.Text strong>
					On every request, your server checks
				</Typography.Text>
				<ul style={{ margin: '4px 0 0', paddingInlineStart: 20 }}>
					<li>the token's aud is exactly {connection.audience};</li>
					<li>its iss is {connection.issuer};</li>
					<li>
						its signature verifies against the keys published at{' '}
						{connection.issuer}/jwks;
					</li>
					<li>it is an access token (typ at+jwt), and it has not expired;</li>
					<li>it is never passed on to another service.</li>
				</ul>
			</div>
		</Space>
	);
}

/* What must be done for calls to reach the API: at the operator's proxy, or in the API's own server (specs/132). */
export function ApiConnectTab({
	bucketId,
	api,
	writable,
	onRefresh
}: {
	bucketId: string;
	api: ResourceView;
	writable: boolean;
	onRefresh: () => void;
}) {
	if (!api.connection) return null;
	if (api.connection.check) {
		return (
			<ProxyConnect
				bucketId={bucketId}
				identifier={api.identifier}
				check={api.connection.check}
				addresses={api.addresses}
				onRefresh={onRefresh}
				writable={writable}
			/>
		);
	}
	return (
		<Flex
			vertical
			gap={16}
		>
			<VouchingStatus
				url={`${resourcesApi(bucketId, api.identifier)}/vouching`}
			/>
			<ResourceConnectionDetails connection={api.connection} />
		</Flex>
	);
}
