import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Descriptions,
	Flex,
	Input,
	Space,
	Tag,
	Typography
} from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { SecretReveal } from '../../frame/SecretReveal.js';
import { bucketHref } from '../../frame/routes.js';
import { Link } from '../../frame/router.js';
import type { BucketView } from '../bucketView.js';
import type { ClientRow, Connection } from './clientForm.js';
import {
	agentBlock,
	describe,
	envBlock,
	guideFor,
	isService,
	lastUsedText,
	scopesToRequest
} from './blocks.js';
import type { HandOff } from './handOff.js';
import { WhoCanSignIn } from './WhoCanSignIn.js';

interface DeclaredApi {
	identifier: string;
	name?: string;
}

/* A value a developer copies into their own configuration; null while the project has no address of its own. */
function Value({ value }: { value: string | null }) {
	return value === null ? (
		<Typography.Text type="secondary">—</Typography.Text>
	) : (
		<Typography.Text
			code
			copyable={{ text: value }}
		>
			{value}
		</Typography.Text>
	);
}

/*
 * One list of addresses an application is allowed to send people to, edited where it is read. Saved through the same
 * update as the Settings tab, so the same rules refuse the same addresses, and a refusal is shown beside the list.
 */
function AddressList({
	label,
	values,
	placeholder,
	writable,
	onSave
}: {
	label: string;
	values: string[];
	placeholder: string;
	writable: boolean;
	onSave: (next: string[]) => Promise<string | null>;
}) {
	const [draft, setDraft] = useState('');
	const [refusal, setRefusal] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);

	async function save(next: string[]) {
		setSaving(true);
		try {
			const problem = await onSave(next);
			setRefusal(problem);
			if (!problem) setDraft('');
		} finally {
			setSaving(false);
		}
	}

	return (
		<Flex
			vertical
			gap={6}
		>
			<Typography.Text strong>{label}</Typography.Text>
			<Space wrap>
				{values.length === 0 && (
					<Typography.Text type="secondary">None</Typography.Text>
				)}
				{values.map((value) => (
					<Tag
						key={value}
						closable={writable && !saving}
						onClose={(e) => {
							e.preventDefault();
							void save(values.filter((v) => v !== value));
						}}
					>
						{value}
					</Tag>
				))}
			</Space>
			{writable && (
				<Space.Compact style={{ maxWidth: 520 }}>
					<Input
						value={draft}
						placeholder={placeholder}
						aria-label={`Add to ${label}`}
						onChange={(e) => setDraft(e.target.value)}
						onPressEnter={(e) => {
							e.preventDefault();
							const next = draft.trim();
							if (next && !values.includes(next)) void save([...values, next]);
						}}
					/>
					<Button
						loading={saving}
						onClick={() => {
							const next = draft.trim();
							if (next && !values.includes(next)) void save([...values, next]);
						}}
					>
						Add
					</Button>
				</Space.Compact>
			)}
			{refusal && (
				<Alert
					type="error"
					showIcon
					title={refusal}
				/>
			)}
		</Flex>
	);
}

/*
 * Everything a developer needs to wire an application up, in the order they need it (spec 107): whether it works yet,
 * what identifies it, the configuration to paste, where the project's sign-in lives, what to ask for, where people
 * may be sent back to, who can sign in, and the ways out — the sign-in page, the agent block, the guide.
 */
export function ConnectTab({
	bucket,
	client,
	writable,
	handed,
	onHandOffUsed,
	onChanged,
	onBucketChanged
}: {
	bucket: BucketView;
	client: ClientRow;
	writable: boolean;
	handed: HandOff | undefined;
	onHandOffUsed: () => void;
	onChanged: (client: ClientRow) => void;
	onBucketChanged: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	// The secret exists only in the answer that minted it: the creation, an edit, or a rotation on this page.
	const [secret, setSecret] = useState<string | undefined>(handed?.secret);
	const [stored, setStored] = useState(false);
	const [showEndpoints, setShowEndpoints] = useState(false);
	const [apis, setApis] = useState<DeclaredApi[] | null>(null);

	const base = `/admin/api/projects/${encodeURIComponent(bucket._id)}`;
	const clientBase = `${base}/clients/${encodeURIComponent(client.clientId)}`;
	const service = isService(client);
	const connection: Connection | undefined = client.connection;

	useEffect(() => {
		if (!service) return;
		void request<{ resources: DeclaredApi[] }>('GET', `${base}/resources`).then(
			(result) => {
				setApis(result.ok ? result.data.resources : []);
			}
		);
	}, [service, base]);

	if (!connection) return null;

	async function patch(body: Record<string, unknown>): Promise<string | null> {
		const result = await request<ClientRow & { secret?: string }>(
			'PATCH',
			clientBase,
			body
		);
		if (!result.ok) {
			if (result.status >= 500) {
				feedback.failed(result);
				return null;
			}
			return result.error.message;
		}
		const { secret: minted, ...next } = result.data;
		if (minted) {
			setSecret(minted);
			setStored(false);
		}
		onChanged(next);
		return null;
	}

	async function rotate() {
		const agreed = await confirm('client.secret.rotate', {
			target: client.clientName || client.clientId,
			consequences: [
				'The current secret stops working immediately.',
				'The application fails to authenticate until it is given the new secret.'
			]
		});
		if (!agreed) return;
		const result = await request<{ secret?: string }>(
			'POST',
			`${clientBase}/secret`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Client secret rotated.');
		if (result.data.secret) {
			setSecret(result.data.secret);
			setStored(false);
		}
	}

	async function copy(text: string, what: string) {
		try {
			await navigator.clipboard.writeText(text);
			feedback.done(`${what} copied.`);
		} catch {
			feedback.refused({
				error: 'clipboard',
				message: 'The browser did not allow copying; select the text instead.'
			});
		}
	}

	const scopes = scopesToRequest(client);
	const lastUsed = connection.lastUsed;
	const guide = guideFor(client);
	const tokenEndpoint = connection.endpoints.token_endpoint;
	const exampleApi = handed?.api ?? apis?.at(0)?.identifier;

	return (
		<Flex
			vertical
			gap={16}
		>
			<Alert
				type={lastUsed ? 'success' : 'info'}
				showIcon
				title={
					lastUsed
						? `${service ? 'Last token' : 'Last sign-in'}: ${lastUsedText(lastUsed)}`
						: service
							? 'Not used yet: this service has not obtained a token.'
							: 'Not used yet: nobody has signed in through this application.'
				}
			/>

			<Card
				size="small"
				title="Your application"
			>
				<Descriptions
					column={1}
					size="small"
					items={[
						{
							key: 'id',
							label: 'Client ID',
							children: <Value value={client.clientId} />
						},
						{ key: 'kind', label: 'Kind', children: describe(client) }
					]}
				/>
				{client.hasSecret && !secret && writable && (
					<Flex
						gap={8}
						align="center"
						style={{ marginTop: 8 }}
					>
						<Typography.Text type="secondary">
							The secret was shown once, when it was created.
						</Typography.Text>
						<Button onClick={() => void rotate()}>Rotate secret</Button>
					</Flex>
				)}
			</Card>

			<Card
				size="small"
				title="Configuration"
				extra={
					<Button
						size="small"
						onClick={() =>
							void copy(
								envBlock(connection, secret, client.hasSecret === true),
								secret ? 'Configuration with the secret' : 'Configuration'
							)
						}
					>
						{secret ? 'Copy with the secret' : 'Copy'}
					</Button>
				}
			>
				<Typography.Paragraph>
					<pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
						{/* On the visit that minted it the secret's line is there, masked; it is revealed and copied below. */}
						{envBlock(
							connection,
							secret ? '•'.repeat(24) : undefined,
							client.hasSecret === true
						)}
					</pre>
				</Typography.Paragraph>
				{secret && (
					<Flex
						vertical
						gap={8}
					>
						<SecretReveal
							secret={secret}
							noun="client secret"
							acknowledged={stored}
							onAcknowledged={setStored}
							acknowledgement="I've put it into the application's configuration"
						/>
						<Button
							disabled={!stored}
							onClick={() => {
								setSecret(undefined);
								onHandOffUsed();
							}}
						>
							Done — hide the secret
						</Button>
					</Flex>
				)}
			</Card>

			<Card
				size="small"
				title="Your project's sign-in"
			>
				{connection.issuer === null ? (
					<Alert
						type="warning"
						showIcon
						title="This project has no address of its own yet"
						description={
							<>
								An application cannot be configured until it has one: every
								value would change the day it gets it.{' '}
								<Link href={bucketHref(bucket._id, 'settings')}>
									Give the project an address
								</Link>
							</>
						}
					/>
				) : (
					<>
						<Descriptions
							column={1}
							size="small"
							items={[
								{
									key: 'issuer',
									label: 'Issuer',
									children: <Value value={connection.issuer} />
								},
								{
									key: 'discovery',
									label: 'Discovery',
									children: <Value value={connection.discoveryUrl} />
								},
								...(showEndpoints
									? Object.entries(connection.endpoints).map(
											([member, url]) => ({
												key: member,
												label: member,
												children: <Value value={url} />
											})
										)
									: [])
							]}
						/>
						<Button
							type="link"
							style={{ paddingInline: 0 }}
							onClick={() => setShowEndpoints((v) => !v)}
						>
							{showEndpoints ? 'Hide endpoints' : 'Show all endpoints'}
						</Button>
					</>
				)}
			</Card>

			{service ? (
				<Card
					size="small"
					title="What it can reach"
				>
					<Typography.Paragraph>
						Its credential can obtain tokens for every API this project
						declares. Ask for one with{' '}
						<Typography.Text code>resource</Typography.Text> set to the
						API&apos;s identifier.
					</Typography.Paragraph>
					{apis === null ? null : apis.length === 0 ? (
						<Typography.Text type="secondary">
							This project declares no API yet.{' '}
							<Link href={`${bucketHref(bucket._id, 'apis')}?declare=1`}>
								Declare one
							</Link>
						</Typography.Text>
					) : (
						<Space wrap>
							{apis.map((api) => (
								<Tag key={api.identifier}>{api.name ?? api.identifier}</Tag>
							))}
						</Space>
					)}
					{tokenEndpoint && exampleApi && (
						<Typography.Paragraph style={{ marginTop: 8 }}>
							<pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
								{`curl -u "$FOXAUTH_CLIENT_ID:$FOXAUTH_CLIENT_SECRET" \\\n  -d grant_type=client_credentials \\\n  -d resource=${exampleApi} \\\n  ${tokenEndpoint}`}
							</pre>
						</Typography.Paragraph>
					)}
				</Card>
			) : (
				<Card
					size="small"
					title="What to request"
				>
					<Typography.Paragraph>
						Scopes: <Typography.Text code>{scopes.base}</Typography.Text>
					</Typography.Paragraph>
					{scopes.withRefresh && (
						<Typography.Paragraph type="secondary">
							For a refresh token, ask for{' '}
							<Typography.Text code>{scopes.withRefresh}</Typography.Text>: one
							is issued only when{' '}
							<Typography.Text code>offline_access</Typography.Text> is
							requested and the person consents to it.
						</Typography.Paragraph>
					)}
				</Card>
			)}

			{!service && (
				<Card
					size="small"
					title="Where people may be sent"
				>
					<Flex
						vertical
						gap={16}
					>
						<AddressList
							label="Callback URLs (redirect URIs)"
							values={client.redirectUris}
							placeholder="https://app.example.com/callback"
							writable={writable}
							onSave={(next) => patch({ redirectUris: next })}
						/>
						<AddressList
							label="After sign-out, return to"
							values={client.postLogoutRedirectUris ?? []}
							placeholder="https://app.example.com"
							writable={writable}
							onSave={(next) => patch({ postLogoutRedirectUris: next })}
						/>
					</Flex>
				</Card>
			)}

			{!service && (
				<WhoCanSignIn
					bucket={bucket}
					onBucketChanged={onBucketChanged}
				/>
			)}

			<Flex
				gap={8}
				wrap
			>
				{connection.signInPageUrl && !service && (
					<Button
						href={connection.signInPageUrl}
						target="_blank"
						rel="noopener"
					>
						Open sign-in page
					</Button>
				)}
				<Button
					onClick={() =>
						void copy(
							agentBlock(client, connection, handed?.api),
							'Instructions for your AI agent'
						)
					}
				>
					Copy for your AI agent
				</Button>
				<Button
					type="link"
					href={guide.href}
					target="_blank"
					rel="noopener"
				>
					{guide.label}
				</Button>
			</Flex>
		</Flex>
	);
}
