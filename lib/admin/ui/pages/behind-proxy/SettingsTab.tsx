import { useMemo, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Flex,
	Form,
	Input,
	Radio,
	Typography
} from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { useLeaveGuard, useNavigate } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import { SaveBar } from '../../settings/SaveBar.js';
import type { Change } from '../../settings/model.js';
import { canonicalAddress } from '../../../../behind_proxy/address.js';
import {
	PROXY_KINDS,
	type ProxyKind
} from '../../../../behind_proxy/recipes.js';
import {
	behindProxyApi,
	hostOfAddress,
	PROXY_LABELS,
	type AppView
} from './appView.js';

interface Values {
	name: string;
	address: string;
	proxyKind: ProxyKind;
}

const LABELS: Record<keyof Values, string> = {
	name: 'Name',
	address: 'Address',
	proxyKind: 'Your proxy'
};

function valuesOf(app: AppView): Values {
	return { name: app.name, address: app.address, proxyKind: app.proxyKind };
}

/*
 * The app's own settings under one save bar (specs/122 FR-038): its name, its address and which proxy's
 * configuration Connect shows first. Deleting is apart from them, and says what it does: the proxy refuses every
 * request to the address from then on.
 */
export function SettingsTab({
	bucketId,
	app,
	writable,
	onChanged
}: {
	bucketId: string;
	app: AppView;
	writable: boolean;
	onChanged: (app: AppView) => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const navigate = useNavigate();
	const [form] = Form.useForm<Values>();
	const baseline = useMemo(() => valuesOf(app), [app]);
	const [values, setValues] = useState<Values>(baseline);
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const host = hostOfAddress(app.address);

	const changed = (Object.keys(LABELS) as (keyof Values)[]).filter(
		(key) => values[key] !== baseline[key]
	);
	const changes: Change[] = changed.map((key) => ({
		key,
		label: LABELS[key],
		group: 'app',
		from: key === 'proxyKind' ? PROXY_LABELS[baseline[key]] : baseline[key],
		to: key === 'proxyKind' ? PROXY_LABELS[values[key]] : values[key]
	}));
	useLeaveGuard(changes.length > 0, changes.length);

	const typed = canonicalAddress(values.address);
	const addressNote =
		values.address !== baseline.address && 'address' in typed
			? `Stored as ${typed.address}. Update your proxy's configuration too: checks for ${host} are refused from then on.`
			: 'People open the app here. A port other than 443 is kept; a path is dropped.';

	async function save() {
		setRefusal(null);
		try {
			await form.validateFields();
		} catch {
			return;
		}
		const body: Partial<Values> = {};
		for (const key of changed) {
			if (key === 'proxyKind') body.proxyKind = values.proxyKind;
			else body[key] = values[key].trim();
		}
		setSaving(true);
		try {
			const result = await request<AppView>(
				'PATCH',
				behindProxyApi(bucketId, app.id),
				body
			);
			if (!result.ok) {
				if (result.status >= 500) feedback.failed(result);
				else if (result.error.field) feedback.refused(result, form);
				else setRefusal(result.error.message);
				return;
			}
			feedback.done(`${result.data.name} saved.`);
			const saved = valuesOf(result.data);
			form.setFieldsValue(saved);
			setValues(saved);
			onChanged(result.data);
		} finally {
			setSaving(false);
		}
	}

	async function remove() {
		const agreed = await confirm('behindProxy.delete', {
			target: app.name,
			consequences: [
				`Your proxy will refuse every request to ${host}.`,
				'Everyone signed in through it is signed out of it.'
			]
		});
		if (!agreed) return;
		const result = await request('DELETE', behindProxyApi(bucketId, app.id));
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${app.name} deleted.`);
		void navigate(bucketHref(bucketId, 'applications'), { replace: true });
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			{refusal && (
				<Alert
					type="error"
					showIcon
					title={refusal}
				/>
			)}
			<Card size="small">
				<Form<Values>
					form={form}
					layout="vertical"
					disabled={!writable}
					initialValues={baseline}
					onValuesChange={(_changed, all) => {
						setRefusal(null);
						setValues(all);
					}}
				>
					<Form.Item
						name="name"
						label="Name"
						rules={[
							{ required: true, whitespace: true, message: 'Name the app.' },
							{ max: 100, message: 'At most 100 characters.' }
						]}
					>
						<Input />
					</Form.Item>
					<Form.Item
						name="address"
						label="Address"
						rules={[
							{ required: true, message: 'Enter the address people open.' },
							{
								validator: async (_rule, value: string | undefined) => {
									if (!value?.trim()) return;
									if ('problem' in canonicalAddress(value)) {
										throw new Error(
											'Enter an https:// address with a host name, such as https://grafana.example.com.'
										);
									}
								}
							}
						]}
						extra={addressNote}
					>
						<Input />
					</Form.Item>
					<Form.Item
						name="proxyKind"
						label="Your proxy"
						extra="Which configuration the Connect tab shows first."
					>
						<Radio.Group
							optionType="button"
							options={PROXY_KINDS.map((kind) => ({
								value: kind,
								label: PROXY_LABELS[kind]
							}))}
						/>
					</Form.Item>
				</Form>
			</Card>
			{writable && (
				<Card
					size="small"
					title="Delete this app"
				>
					<Flex
						gap={8}
						align="center"
						wrap
					>
						<Typography.Text type="secondary">
							Your proxy will refuse every request to {host}.
						</Typography.Text>
						<Button
							danger
							onClick={() => void remove()}
						>
							Delete…
						</Button>
					</Flex>
				</Card>
			)}
			{writable && (
				<SaveBar
					changes={changes}
					saving={saving}
					onSave={() => void save()}
					onDiscard={() => {
						setRefusal(null);
						form.setFieldsValue(baseline);
						setValues(baseline);
					}}
				/>
			)}
		</Flex>
	);
}
