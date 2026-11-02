import { useEffect, useState } from 'react';
import { Checkbox, Card, Flex, Typography } from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { bucketHref } from '../../frame/routes.js';
import { Link } from '../../frame/router.js';
import type { ClientRow } from './clientForm.js';
import { whyCannotExchange } from './exchange.js';

interface ServiceSummary {
	id: string;
	displayName: string;
	identifier: string;
	applications: string[];
}

/*
 * The project's connected services this application may obtain people's tokens at (specs/118). Each box edits that
 * service's list of applications, the same list its editor on the Connected services page shows; the server checks
 * every entry, so a refusal here is its answer, by name.
 */
export function ConnectedServicesCard({
	bucketId,
	client,
	writable
}: {
	bucketId: string;
	client: ClientRow;
	writable: boolean;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [services, setServices] = useState<ServiceSummary[] | null>(null);
	const [saving, setSaving] = useState<string | null>(null);
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}/connected-services`;

	useEffect(() => {
		let live = true;
		void request<{ services: ServiceSummary[] }>('GET', base).then((result) => {
			if (live) setServices(result.ok ? result.data.services : []);
		});
		return () => {
			live = false;
		};
	}, [base]);

	if (!services || services.length === 0) return null;

	const why = whyCannotExchange(client);

	async function toggle(service: ServiceSummary, allowed: boolean) {
		await confirm('connectedService.edit', { target: service.displayName });
		const next = allowed
			? [...service.applications, client.clientId]
			: service.applications.filter((id) => id !== client.clientId);
		setSaving(service.id);
		try {
			const result = await request<ServiceSummary>(
				'PATCH',
				`${base}/${encodeURIComponent(service.id)}`,
				{ applications: next }
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			setServices((current) =>
				(current ?? []).map((item) =>
					item.id === service.id ? result.data : item
				)
			);
			feedback.done(
				allowed
					? `${service.displayName} now lets this application obtain tokens.`
					: `${service.displayName} no longer lets this application obtain tokens.`
			);
		} finally {
			setSaving(null);
		}
	}

	return (
		<Card
			size="small"
			title="Connected services"
		>
			{why ? (
				<Typography.Paragraph
					type="secondary"
					style={{ margin: 0 }}
				>
					This application cannot obtain people&apos;s tokens at{' '}
					<Link href={bucketHref(bucketId, 'connected-services')}>
						connected services
					</Link>
					: {why}.
				</Typography.Paragraph>
			) : (
				<Flex
					vertical
					gap={8}
				>
					<Typography.Text type="secondary">
						It can obtain a person&apos;s token at a service checked here, only
						after that person allows it. Unchecking stops its next request;
						tokens it already received stay valid at the provider until they
						expire.
					</Typography.Text>
					{services.map((service) => (
						<Checkbox
							key={service.id}
							checked={service.applications.includes(client.clientId)}
							disabled={!writable || saving !== null}
							onChange={(event) => void toggle(service, event.target.checked)}
						>
							{service.displayName}{' '}
							<Typography.Text
								type="secondary"
								code
							>
								{service.identifier}
							</Typography.Text>
						</Checkbox>
					))}
				</Flex>
			)}
		</Card>
	);
}
