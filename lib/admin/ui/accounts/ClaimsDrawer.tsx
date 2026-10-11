import { useEffect, useState } from 'react';
import { Button, Drawer, Form, Input, Space, Typography } from 'antd';
import { RESERVED_CLAIMS } from '../../../consts/reserved_claims.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';

/*
 * The claims an account releases, edited as JSON text in a side panel and saved in one request
 * (specs/082 FR-008). Parsed here to refuse what is not an object, and a reserved name on the field itself,
 * before a round trip; the server holds the same list (lib/consts/reserved_claims.ts) and refuses the same.
 */
export function parseClaims(text: string | undefined): Record<string, unknown> {
	const trimmed = text?.trim();
	if (!trimmed) return {};
	const value: unknown = JSON.parse(trimmed);
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		throw new TypeError('claims must be a JSON object');
	}
	const reserved = Object.keys(value).filter((name) =>
		RESERVED_CLAIMS.includes(name)
	);
	if (reserved.length > 0) {
		throw new TypeError(
			`${reserved.join(', ')} come${reserved.length === 1 ? 's' : ''} from the account itself and cannot be set here`
		);
	}
	return value as Record<string, unknown>;
}

export function ClaimsField({ name = 'claimsText' }: { name?: string }) {
	return (
		<Form.Item
			name={name}
			label="Claims"
			tooltip='JSON, e.g. {"name":"Ada Lovelace","locale":"en-GB"}. Released to a client only when the claims setting names them under a scope the client was granted.'
			rules={[
				{
					validator: async (_rule, text: string | undefined) => {
						parseClaims(text);
					}
				}
			]}
		>
			<Input.TextArea
				rows={8}
				spellCheck={false}
				placeholder='{"name":"Ada Lovelace"}'
			/>
		</Form.Item>
	);
}

export function ClaimsDrawer({
	account,
	url,
	open,
	onClose,
	onDone
}: {
	account: { email: string; claims?: Record<string, unknown> };
	/* PATCH { claims }: the whole set is replaced, so an emptied field clears them. */
	url: string;
	open: boolean;
	onClose: () => void;
	onDone: () => void;
}) {
	const [form] = Form.useForm<{ claimsText?: string }>();
	const feedback = useFeedback();
	const [saving, setSaving] = useState(false);

	useEffect(() => {
		if (open) {
			form.setFieldsValue({
				claimsText:
					account.claims && Object.keys(account.claims).length > 0
						? JSON.stringify(account.claims, null, 2)
						: ''
			});
		}
	}, [open, account.claims, form]);

	async function onFinish({ claimsText }: { claimsText?: string }) {
		setSaving(true);
		try {
			const result = await request('PATCH', url, {
				claims: parseClaims(claimsText)
			});
			if (!result.ok) {
				feedback.failed(result, form);
				if (result.error.field === 'claims') {
					form.setFields([
						{ name: 'claimsText', errors: [result.error.message] }
					]);
				}
				return;
			}
			feedback.done(`Claims of ${account.email} saved.`);
			onClose();
			onDone();
		} finally {
			setSaving(false);
		}
	}

	return (
		<Drawer
			title={`Claims — ${account.email}`}
			open={open}
			onClose={onClose}
			size="large"
			destroyOnHidden
			extra={
				<Space>
					<Button onClick={onClose}>Cancel</Button>
					<Button
						type="primary"
						loading={saving}
						onClick={() => form.submit()}
					>
						Save
					</Button>
				</Space>
			}
		>
			<Typography.Paragraph type="secondary">
				{RESERVED_CLAIMS.slice(0, 3).join(', ')} and the other names the server
				asserts itself come from the account and cannot be set here.
			</Typography.Paragraph>
			<Form<{ claimsText?: string }>
				form={form}
				layout="vertical"
				onFinish={(values) => void onFinish(values)}
			>
				<ClaimsField />
			</Form>
		</Drawer>
	);
}
