import { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Flex, Form, Typography } from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { SecretReveal } from '../../frame/SecretReveal.js';
import { useLeaveGuard, useNavigate } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import { SaveBar } from '../../settings/SaveBar.js';
import type { Change } from '../../settings/model.js';
import type { BucketView } from '../bucketView.js';
import {
	buildBody,
	formValuesOf,
	type ClientRow,
	type FormValues
} from './clientForm.js';
import { ClientFormFields } from './ClientFormFields.js';

function same(a: unknown, b: unknown): boolean {
	return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/*
 * Every setting an application has, under one save bar (spec 107). This is the only place an application's settings
 * are edited, so what it saves is exactly what the edit window used to: the same body, the same refusals.
 */
export function SettingsTab({
	bucket,
	client,
	writable,
	onChanged
}: {
	bucket: BucketView;
	client: ClientRow;
	writable: boolean;
	onChanged: (client: ClientRow) => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const navigate = useNavigate();
	const [form] = Form.useForm<FormValues>();
	const baseline = useMemo(() => formValuesOf(client), [client]);
	const [values, setValues] = useState<FormValues>(baseline);
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const [secret, setSecret] = useState<string | null>(null);
	const [stored, setStored] = useState(false);
	const [siblings, setSiblings] = useState<
		{ label: string; origins: string[] }[]
	>([]);

	const base = `/admin/api/projects/${encodeURIComponent(bucket._id)}/clients`;

	// The other applications of the project with browser origins, offered to copy from.
	useEffect(() => {
		void request<ClientRow[]>('GET', base).then((result) => {
			if (!result.ok) return;
			setSiblings(
				result.data
					.filter(
						(row) =>
							row.clientId !== client.clientId &&
							(row.corsOrigins?.length ?? 0) > 0
					)
					.map((row) => ({
						label: row.clientName || row.clientId,
						origins: row.corsOrigins ?? []
					}))
			);
		});
	}, [base, client.clientId]);

	const changes: Change[] = (
		Object.keys({ ...baseline, ...values }) as (keyof FormValues)[]
	)
		.filter((key) => !same(baseline[key], values[key]))
		.map((key) => ({
			key,
			label: key,
			group: 'application',
			from: baseline[key],
			to: values[key]
		}));
	useLeaveGuard(changes.length > 0, changes.length);

	async function save() {
		setRefusal(null);
		let current: FormValues;
		try {
			current = await form.validateFields();
		} catch {
			return;
		}
		setSaving(true);
		try {
			const result = await request<ClientRow & { secret?: string }>(
				'PATCH',
				`${base}/${encodeURIComponent(client.clientId)}`,
				buildBody(current, {
					logo: client.logo ?? null,
					primaryColor: client.primaryColor ?? null
				})
			);
			if (!result.ok) {
				if (result.status >= 500) feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			const { secret: minted, ...next } = result.data;
			feedback.done('Application saved.');
			if (minted) {
				setSecret(minted);
				setStored(false);
			}
			// What was saved is the new baseline: the form shows the stored values, and nothing reads as unsaved.
			const saved = formValuesOf(next);
			form.setFieldsValue(saved);
			setValues(saved);
			onChanged(next);
		} finally {
			setSaving(false);
		}
	}

	/*
	 * States the consequence rather than asking for confirmation of an unstated one: deleting a client
	 * destroys every credential it ever issued, and the invisible half of that is what an operator
	 * cannot otherwise see.
	 */
	async function remove() {
		const agreed = await confirm('client.delete', {
			target: client.clientName || client.clientId,
			consequences: [
				'Its access, refresh and machine-to-machine tokens stop working immediately.',
				'Its pending codes and consent records are destroyed.',
				'Its own registration credential is destroyed.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(client.clientId)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Application deleted.');
		void navigate(bucketHref(bucket._id, 'applications'));
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			{secret && (
				<Card
					size="small"
					title="The new client secret"
				>
					<Flex
						vertical
						gap={8}
					>
						<Typography.Text>
							This change gave the application a secret. It is shown only now.
						</Typography.Text>
						<SecretReveal
							secret={secret}
							noun="client secret"
							acknowledged={stored}
							onAcknowledged={setStored}
							acknowledgement="I've put it into the application's configuration"
						/>
						<Button
							disabled={!stored}
							onClick={() => setSecret(null)}
						>
							Done — hide the secret
						</Button>
					</Flex>
				</Card>
			)}
			{refusal && (
				<Alert
					type="error"
					showIcon
					title={refusal}
				/>
			)}
			<Form<FormValues>
				form={form}
				layout="vertical"
				scrollToFirstError
				disabled={!writable}
				initialValues={baseline}
				onValuesChange={(_changed, all) => {
					setRefusal(null);
					setValues(all);
				}}
			>
				<ClientFormFields
					form={form}
					siblings={siblings}
				/>
			</Form>
			{writable && (
				<Card
					size="small"
					title="Delete this application"
				>
					<Flex
						gap={8}
						align="center"
						wrap
					>
						<Typography.Text type="secondary">
							Its tokens stop working at once and cannot be brought back.
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
