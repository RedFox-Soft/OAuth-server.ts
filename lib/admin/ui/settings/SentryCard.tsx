import { useCallback, useEffect, useState } from 'react';
import { Button, Card, Form, Input, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { LoadFailed } from '../frame/states.js';

interface SentryView {
	enabled: boolean;
	configured: boolean;
	environment: string;
	release: string;
	/*
	 * Stored here but not what this process is running. Empty on a healthy instance, because both of
	 * this card's settings are applied when they are saved — which is what the tag below now reports
	 * instead of asserting.
	 */
	notInForceKeys: string[];
}

/*
 * The Sentry credential, and the state of reporting.
 *
 * Two shapes, not one form. With nothing stored there is something to type, so the input is shown.
 * Once a credential is stored there is nothing to type — it can never be read back — so the input
 * disappears and the only action left is to remove it. Leaving a permanently-blank password box on
 * screen invites an operator to wonder what belongs in it.
 *
 * Removing also switches reporting off, in one call. It has to: enabling with no credential is a
 * configuration the server refuses, so clearing one while reporting was on would produce a state
 * that cannot be saved. One button that means "stop reporting and forget the credential" is the
 * only coherent action, and it is what an operator wants anyway.
 *
 * The environment and release are shown read-only. They are resolved from the deployment rather than
 * stored, so this is the one place an operator can confirm which build an alert will be filed under.
 *
 * Rendered inside the Diagnostics pane beside the Error Store card rather than nested inside it.
 * Nesting it in an accordion panel — which is where it used to live — put a card inside a panel
 * inside a page, and hid the credential behind a disclosure that had to be open before an operator
 * could satisfy the prerequisite for the toggle above it.
 */
export function SentryCard() {
	const [form] = Form.useForm<{ dsn: string }>();
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [view, setView] = useState<SentryView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);
	const feedback = useFeedback();
	const confirm = useConfirm();

	// Every state write follows an await: `loading` starts true, so the mount has nothing to set first.
	const load = useCallback(async () => {
		try {
			const result = await request<SentryView>(
				'GET',
				'/admin/api/settings/sentry'
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

	/*
	 * `enabled` is echoed back at whatever the card last read, because the endpoint is a full replace.
	 * Read rather than assumed, so saving a credential cannot silently revert a toggle changed in the
	 * card beside it.
	 */
	async function submit(next: { dsn: string; enabled: boolean }) {
		if (!view) return;
		setSaving(true);
		try {
			const result = await request<SentryView>(
				'PUT',
				'/admin/api/settings/sentry',
				{ enabled: next.enabled, dsn: next.dsn }
			);
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			setView(result.data);
			form.resetFields();
			feedback.done(
				next.dsn
					? 'Sentry credential saved.'
					: 'Sentry reporting disabled and its credential removed.'
			);
		} finally {
			setSaving(false);
		}
	}

	async function disable() {
		const yes = await confirm('sentry.disable', {
			target: 'Sentry',
			consequences: [
				'Server faults are no longer reported to Sentry.',
				'The stored credential is removed and has to be pasted again to resume reporting.'
			]
		});
		if (yes) await submit({ dsn: '', enabled: false });
	}

	const configured = view?.configured === true;

	return (
		<Card
			title="Sentry credential"
			size="small"
			style={{ marginBottom: 16 }}
			loading={loading}
			extra={
				<span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
					{view && view.notInForceKeys.length > 0 ? (
						<Tag color="orange">saved, not in force here</Tag>
					) : (
						<Tag color="green">applies immediately</Tag>
					)}
					{configured ? (
						<Tag color={view.enabled ? 'green' : 'default'}>
							{view.enabled ? 'reporting' : 'stored, off'}
						</Tag>
					) : (
						<Tag color="orange">no credential</Tag>
					)}
				</span>
			}
		>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={reload}
				/>
			) : configured ? (
				<>
					<Typography.Paragraph
						type="secondary"
						style={{ marginBottom: 8 }}
					>
						A credential is stored and cannot be shown again. Events are filed
						under environment <strong>{view.environment || 'unknown'}</strong>
						{view.release ? (
							<>
								{' '}
								and release <strong>{view.release}</strong>
							</>
						) : (
							' with no release label'
						)}
						.
					</Typography.Paragraph>
					<Button
						danger
						loading={saving}
						onClick={() => void disable()}
					>
						Disable and remove credential
					</Button>
				</>
			) : (
				<>
					<Typography.Paragraph
						type="secondary"
						style={{ marginBottom: 8 }}
					>
						Paste the receiving project&apos;s ingestion credential. Reporting
						cannot be switched on until one is stored.
					</Typography.Paragraph>
					<Form<{ dsn: string }>
						form={form}
						layout="vertical"
						scrollToFirstError
						onFinish={(v) =>
							submit({ dsn: v.dsn, enabled: view?.enabled ?? false })
						}
					>
						<Form.Item
							name="dsn"
							label="Ingestion credential (DSN)"
							rules={[{ required: true, message: 'a credential is required' }]}
						>
							<Input.Password
								autoComplete="new-password"
								placeholder="https://…@….ingest.sentry.io/…"
							/>
						</Form.Item>
						<Button
							type="primary"
							loading={saving}
							onClick={() => form.submit()}
						>
							Save credential
						</Button>
					</Form>
				</>
			)}
		</Card>
	);
}
