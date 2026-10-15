import { useEffect, useState } from 'react';
import { Alert, Card, Descriptions, Space, Tag, Typography } from 'antd';
import { Link } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';

interface Published {
	kid: string;
	alg?: string;
}

/*
 * The Signing keys tab of a bucket served at the root issuer (specs/086). It has no keys of its own, and saying
 * only "managed elsewhere" was a dead end for a group member who cannot open the instance Keys page. So it
 * answers both questions it gets: an integrator's ("which keys verify my tokens?"), from the public key set any
 * relying party reads, and an administrator's ("can I rotate them?"), with the one way to keys of its own.
 */
export function RootKeysCard({
	bucketId,
	bucketName,
	superAdmin
}: {
	bucketId: string;
	bucketName: string;
	superAdmin: boolean;
}) {
	const [issuer, setIssuer] = useState<string | null>(null);
	const [keySet, setKeySet] = useState<string | null>(null);
	const [published, setPublished] = useState<Published[] | null>(null);

	useEffect(() => {
		void (async () => {
			try {
				// The root discovery document, public and on this origin, like the key set it names.
				const discovery = (await (
					await fetch('/.well-known/openid-configuration')
				).json()) as { issuer?: string; jwks_uri?: string };
				setIssuer(discovery.issuer ?? null);
				setKeySet(discovery.jwks_uri ?? null);
				if (!discovery.jwks_uri) return;
				const url = new URL(discovery.jwks_uri, window.location.origin);
				// Another origin is refused by the console's own content policy; the address alone still answers.
				if (url.origin !== window.location.origin) return;
				const jwks = (await (await fetch(url.pathname)).json()) as {
					keys?: Published[];
				};
				setPublished(jwks.keys ?? []);
			} catch {
				// Unreadable: the explanation stands without the list.
			}
		})();
	}, []);

	return (
		<Card title="This project signs with the instance keys">
			<Space
				orientation="vertical"
				style={{ width: '100%' }}
			>
				<Alert
					type="info"
					showIcon
					title={`${bucketName} has no address of its own.`}
					description={`It is served at the root issuer${issuer ? ` ${issuer}` : ''} and shares that issuer's key set with the default project, the administrators' sign-in and every other project without an address.`}
				/>
				<Descriptions
					column={1}
					size="small"
					items={[
						...(keySet
							? [
									{
										key: 'set',
										label: 'Key set',
										children: (
											<Typography.Text
												code
												copyable
											>
												{keySet}
											</Typography.Text>
										)
									}
								]
							: []),
						...(published
							? [
									{
										key: 'published',
										label: 'Published',
										children:
											published.length === 0 ? (
												'—'
											) : (
												<Space wrap>
													{published.map((k) => (
														<span key={k.kid}>
															<Typography.Text code>{k.kid}</Typography.Text>
															{k.alg ? (
																<Tag style={{ marginLeft: 4 }}>{k.alg}</Tag>
															) : null}
														</span>
													))}
												</Space>
											)
									}
								]
							: [])
					]}
				/>
				<Typography.Text type="secondary">
					Read from the public key set. Which of them signs is shown to instance
					administrators on the Keys page.
				</Typography.Text>
				<Typography.Text>
					To rotate this project&apos;s keys on its own, give it an address of
					its own.{' '}
					{!superAdmin &&
						'Only an instance administrator can change the address or the instance keys.'}
				</Typography.Text>
				{superAdmin && (
					<Space size="large">
						{/* The default bucket is served at the root by definition, so it has no address to give. */}
						{bucketId !== 'redfox' && (
							<Link href={bucketHref(bucketId, 'settings')}>
								Change address…
							</Link>
						)}
						<Link href="/admin/keys">Open instance keys</Link>
					</Space>
				)}
			</Space>
		</Card>
	);
}
