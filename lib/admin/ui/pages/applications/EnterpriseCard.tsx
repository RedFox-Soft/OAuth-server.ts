import { useEffect, useState } from 'react';
import { Card, Flex, Typography } from 'antd';
import { request } from '../../frame/request.js';
import { bucketHref, providerHref } from '../../frame/routes.js';
import { Link } from '../../frame/router.js';

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

interface OutsideServer {
	id: string;
	displayName: string;
	issuer: string;
	applications: { clientId: string }[];
}

interface Provider {
	id: string;
	displayName: string;
	acceptsIdentityAssertions?: boolean;
	plainAssertions?: { applications: string[] };
}

/*
 * Where an application's assertion grants reach (specs/108): the outside servers that let it ask for ID-JAGs,
 * and the providers whose assertions it may present. An ID-JAG names its client, so a provider trusted for
 * them is listed for every application with the grant; a plain assertion does not, so only the applications
 * the trust names are listed for it.
 */
export function EnterpriseCard({
	bucketId,
	clientId,
	grantTypes
}: {
	bucketId: string;
	clientId: string;
	grantTypes: string[];
}) {
	const exchanges = grantTypes.includes(TOKEN_EXCHANGE);
	const presents = grantTypes.includes(JWT_BEARER);
	const [servers, setServers] = useState<OutsideServer[] | null>(null);
	const [providers, setProviders] = useState<Provider[] | null>(null);
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}`;

	useEffect(() => {
		if (!exchanges) return;
		let live = true;
		void request<OutsideServer[]>(
			'GET',
			`${base}/outside-authorization-servers`
		).then((result) => {
			if (live) setServers(result.ok ? result.data : []);
		});
		return () => {
			live = false;
		};
	}, [base, exchanges]);

	useEffect(() => {
		if (!presents) return;
		let live = true;
		void request<Provider[]>('GET', `${base}/federation`).then((result) => {
			if (live) setProviders(result.ok ? result.data : []);
		});
		return () => {
			live = false;
		};
	}, [base, presents]);

	if (!exchanges && !presents) return null;

	const allowedOn = (servers ?? []).filter((server) =>
		server.applications.some((application) => application.clientId === clientId)
	);
	const trusting = (providers ?? []).flatMap((provider) => {
		const kinds = [
			...(provider.acceptsIdentityAssertions ? ['ID-JAG'] : []),
			...(provider.plainAssertions?.applications.includes(clientId)
				? ['plain assertions']
				: [])
		];
		return kinds.length ? [{ provider, kinds }] : [];
	});

	return (
		<Card
			size="small"
			title="Enterprise-managed authorization"
		>
			<Flex
				vertical
				gap={8}
			>
				{exchanges && (
					<div>
						<Typography.Text>
							Exchanges a person's ID token for an ID-JAG for these{' '}
							<Link href={bucketHref(bucketId, 'outside-servers')}>
								outside servers
							</Link>
							:
						</Typography.Text>
						{servers !== null && allowedOn.length === 0 ? (
							<Typography.Paragraph type="secondary">
								None allows it yet.
							</Typography.Paragraph>
						) : (
							<ul>
								{allowedOn.map((server) => (
									<li key={server.id}>
										{server.displayName}{' '}
										<Typography.Text type="secondary">
											{server.issuer}
										</Typography.Text>
									</li>
								))}
							</ul>
						)}
					</div>
				)}
				{presents && (
					<div>
						<Typography.Text>
							Presents assertions from these{' '}
							<Link href={bucketHref(bucketId, 'identity-providers')}>
								identity providers
							</Link>
							:
						</Typography.Text>
						{providers !== null && trusting.length === 0 ? (
							<Typography.Paragraph type="secondary">
								No provider is trusted for them yet.
							</Typography.Paragraph>
						) : (
							<ul>
								{trusting.map(({ provider, kinds }) => (
									<li key={provider.id}>
										<Link href={providerHref(bucketId, provider.id)}>
											{provider.displayName}
										</Link>{' '}
										<Typography.Text type="secondary">
											{kinds.join(', ')}
										</Typography.Text>
									</li>
								))}
							</ul>
						)}
					</div>
				)}
			</Flex>
		</Card>
	);
}
