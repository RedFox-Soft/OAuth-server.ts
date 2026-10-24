import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Button, Card, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';

interface Violation {
	rule: string;
	attribute: string;
	value?: string;
	cites: string;
}

interface Readiness {
	enabled: boolean;
	canEnable: boolean;
	settings: { key: string; required: string; actual: unknown }[];
	issuers: {
		issuer: string;
		projectId?: string;
		signingAlgorithms: string[];
	}[];
	clients: {
		projectId: string;
		clientId: string;
		clientName?: string;
		violations: Violation[];
	}[];
}

/* The operator's words for each rule the profile applies to an application. */
const RULE_TEXT: Record<string, string> = {
	http_redirect_uri: 'redirect URI uses http',
	response_type_none: 'registered for response_type=none',
	signing_algorithm: 'algorithm outside PS256, ES256, EdDSA',
	client_secret_jwt: 'authenticates with client_secret_jwt',
	certificate_bound_tokens: 'asks for certificate-bound tokens',
	default_algorithm: 'registered no algorithm: will be signed for PS256'
};

function describe(v: Violation): string {
	const what = RULE_TEXT[v.rule] ?? v.rule;
	return `${what} (${v.attribute}${v.value ? `: ${v.value}` : ''}; ${v.cites})`;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
	return (
		<>
			<Typography.Text strong>{title}</Typography.Text>
			<ul style={{ margin: '4px 0 12px', paddingInlineStart: 20 }}>
				{children}
			</ul>
		</>
	);
}

/*
 * What turning the IPSIE SL1 profile on would need and refuse, read before the switch beside it is flipped. Read
 * on demand rather than saved with the page: it is computed from every project's applications and keys, and it
 * changes when they do, not when a setting on this page does.
 */
export function Sl1ReadinessCard() {
	const [loading, setLoading] = useState(true);
	const [view, setView] = useState<Readiness | null>(null);
	const [failed, setFailed] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const result = await request<Readiness>(
				'GET',
				'/admin/api/settings/ipsie-sl1/readiness'
			);
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setView(result.data);
		} finally {
			setLoading(false);
		}
	}, []);
	function reload() {
		setLoading(true);
		void load();
	}
	useEffect(() => {
		void load();
	}, [load]);

	const status = !view ? null : view.enabled ? (
		<Tag color="green">On</Tag>
	) : view.canEnable ? (
		<Tag color="blue">Can be turned on</Tag>
	) : (
		<Tag color="orange">Not ready</Tag>
	);

	return (
		<Card
			title="IPSIE SL1 readiness"
			loading={loading && !view}
			style={{ marginBottom: 16 }}
			extra={
				<>
					{status}
					<Button
						size="small"
						onClick={reload}
						loading={loading}
					>
						Check again
					</Button>
				</>
			}
		>
			{failed ? (
				<LoadFailed
					reason={failed}
					onRetry={reload}
				/>
			) : view ? (
				<>
					<Typography.Paragraph type="secondary">
						Nothing here changes a setting or an application. The switch above
						is refused while a setting or an issuer below is listed; the
						applications listed keep their records and are refused, or signed
						for PS256, once the profile is on.
					</Typography.Paragraph>
					{view.settings.length > 0 && (
						<Section title="Settings that stand in the way">
							{view.settings.map((setting) => (
								<li key={setting.key}>
									<Typography.Text code>{setting.key}</Typography.Text>
									{` must be ${setting.required}`}
								</li>
							))}
						</Section>
					)}
					{view.issuers.length > 0 && (
						<Section title="Issuers without a PS256 signing key (generate and promote one)">
							{view.issuers.map((issuer) => (
								<li key={issuer.issuer}>
									{`${issuer.issuer} — signs with ${issuer.signingAlgorithms.join(', ') || 'nothing'}`}
								</li>
							))}
						</Section>
					)}
					{view.clients.length > 0 && (
						<Section title="Applications the profile would refuse or change">
							{view.clients.map((client) => (
								<li key={client.clientId}>
									<Typography.Text strong>
										{`${client.clientName ?? client.clientId} (project ${client.projectId})`}
									</Typography.Text>
									{`: ${client.violations.map(describe).join('; ')}`}
								</li>
							))}
						</Section>
					)}
					{view.settings.length === 0 &&
						view.issuers.length === 0 &&
						view.clients.length === 0 && (
							<Typography.Text>Nothing stands in the way.</Typography.Text>
						)}
				</>
			) : null}
		</Card>
	);
}
