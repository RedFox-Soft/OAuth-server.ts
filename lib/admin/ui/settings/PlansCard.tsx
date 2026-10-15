import { useCallback, useEffect, useState } from 'react';
import {
	Button,
	Card,
	Checkbox,
	Flex,
	Form,
	Input,
	InputNumber,
	Modal,
	Switch,
	Table,
	Tag,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { Plan } from '../../../consts/plans.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { LoadFailed } from '../frame/states.js';
import {
	FEATURE_LABEL,
	FEATURE_ORDER,
	LIMIT_LABEL,
	LIMIT_ORDER,
	limitText,
	type PlanLimitKey
} from '../planText.js';

type CataloguePlan = Plan & { projects: number };

interface PlanFormValues {
	id: string;
	name: string;
	limits: Record<PlanLimitKey, number | null>;
	unlimited: Record<PlanLimitKey, boolean>;
	features: Plan['features'];
}

const BLANK: Plan = {
	id: '',
	name: '',
	default: false,
	limits: {
		monthlyActiveUsers: null,
		projectsPerAdministrator: null,
		applicationsPerProject: null,
		apisPerProject: null
	},
	features: { enterpriseSignIn: false, customSlug: false, customDomain: false }
};

function formValuesOf(plan: Plan): PlanFormValues {
	const limits = {} as Record<PlanLimitKey, number | null>;
	const unlimited = {} as Record<PlanLimitKey, boolean>;
	for (const key of LIMIT_ORDER) {
		limits[key] = plan.limits[key];
		unlimited[key] = plan.limits[key] === null;
	}
	return {
		id: plan.id,
		name: plan.name,
		limits,
		unlimited,
		features: { ...plan.features }
	};
}

/*
 * The plan catalogue (specs/102), on the Plans & limits pane beside the two settings that turn it on.
 *
 * Its own endpoint, saved per action like the SMTP and Sentry cards, and in force at once: a changed limit applies
 * to every project on the plan from the next check. A plan in use cannot be deleted; the server's refusal says
 * how many projects are on it, and is shown as it stands.
 */
export function PlansCard() {
	const [plans, setPlans] = useState<CataloguePlan[]>([]);
	const [loading, setLoading] = useState(true);
	const [failed, setFailed] = useState<string | null>(null);
	// The plan being edited, a blank one for Add, or null while the dialog is closed.
	const [editing, setEditing] = useState<{
		plan: Plan;
		create: boolean;
	} | null>(null);
	const [saving, setSaving] = useState(false);
	const [form] = Form.useForm<PlanFormValues>();
	const feedback = useFeedback();
	const confirm = useConfirm();

	// Every state write follows an await: `loading` starts true, so the mount has nothing to set first.
	const load = useCallback(async () => {
		try {
			const result = await request<{ plans: CataloguePlan[] }>(
				'GET',
				'/admin/api/plans'
			);
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setPlans(result.data.plans);
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

	async function save(values: PlanFormValues) {
		if (!editing) return;
		const limits = {} as Plan['limits'];
		for (const key of LIMIT_ORDER) {
			limits[key] = values.unlimited[key] ? null : (values.limits[key] ?? 0);
		}
		const name = values.name.trim();
		setSaving(true);
		try {
			const result = editing.create
				? await request<Plan>('POST', '/admin/api/plans', {
						id: values.id,
						name,
						default: false,
						limits,
						features: values.features
					})
				: await request<Plan>(
						'PATCH',
						`/admin/api/plans/${encodeURIComponent(editing.plan.id)}`,
						{ name, limits, features: values.features }
					);
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			feedback.done(
				editing.create ? `Plan ${name} added.` : `Plan ${name} saved.`
			);
			setEditing(null);
			reload();
		} finally {
			setSaving(false);
		}
	}

	async function makeDefault(plan: CataloguePlan) {
		const agreed = await confirm('plan.makeDefault', {
			target: plan.name,
			consequences: [
				'Every project created from now on is put on this plan.',
				'Projects already on another plan stay where they are.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'PATCH',
			`/admin/api/plans/${encodeURIComponent(plan.id)}`,
			{ default: true }
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${plan.name} is now the default plan.`);
		reload();
	}

	async function remove(plan: CataloguePlan) {
		const agreed = await confirm('plan.delete', {
			target: plan.name,
			consequences: ['It is removed from the catalogue.']
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`/admin/api/plans/${encodeURIComponent(plan.id)}`
		);
		if (!result.ok) {
			// A plan with projects on it is refused with their count, which is the message.
			feedback.failed(result);
			return;
		}
		feedback.done(`Plan ${plan.name} deleted.`);
		reload();
	}

	function actionsFor(plan: CataloguePlan): RowAction[] {
		const items: RowAction[] = [
			{
				key: 'edit',
				label: 'Edit…',
				group: 'edit',
				onClick: () => setEditing({ plan, create: false })
			}
		];
		if (!plan.default) {
			items.push({
				key: 'default',
				label: 'Make default',
				group: 'state',
				onClick: () => void makeDefault(plan)
			});
		}
		items.push({
			key: 'delete',
			label: 'Delete',
			group: 'danger',
			blocked: plan.default
				? 'The default plan cannot be deleted: make another plan the default first.'
				: null,
			onClick: () => void remove(plan)
		});
		return items;
	}

	return (
		<Card
			title="Plans"
			size="small"
			style={{ marginBottom: 16 }}
			extra={
				<span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
					<Tag color="green">applies immediately</Tag>
					<Button
						icon={<PlusOutlined />}
						disabled={failed !== null}
						onClick={() => setEditing({ plan: BLANK, create: true })}
					>
						Add plan
					</Button>
				</span>
			}
		>
			<Typography.Paragraph type="secondary">
				Every project is on one plan, and a new project is put on the default
				plan. A limit applies to the next creation only — nothing that exists is
				switched off — and never to a super administrator or a System project.
			</Typography.Paragraph>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={reload}
				/>
			) : (
				<Table<CataloguePlan>
					rowKey="id"
					size="small"
					loading={loading}
					dataSource={plans}
					pagination={false}
					scroll={{ x: 'max-content' }}
					columns={[
						{
							title: 'Plan',
							key: 'name',
							render: (_: unknown, plan: CataloguePlan) => (
								<Flex
									vertical
									gap={2}
								>
									<span>
										{plan.name}{' '}
										{plan.default && <Tag color="blue">Default</Tag>}
									</span>
									<Typography.Text
										type="secondary"
										code
									>
										{plan.id}
									</Typography.Text>
								</Flex>
							)
						},
						{
							title: 'Limits',
							key: 'limits',
							render: (_: unknown, plan: CataloguePlan) => (
								<Flex
									vertical
									gap={2}
								>
									{LIMIT_ORDER.map((key) => (
										<span key={key}>
											{LIMIT_LABEL[key]}: {limitText(plan.limits[key])}
										</span>
									))}
								</Flex>
							)
						},
						{
							title: 'Features',
							key: 'features',
							render: (_: unknown, plan: CataloguePlan) => (
								<Flex
									vertical
									gap={2}
								>
									{FEATURE_ORDER.map((key) => (
										<span key={key}>
											{FEATURE_LABEL[key]}:{' '}
											{plan.features[key] ? (
												'included'
											) : (
												<Typography.Text type="secondary">
													not included
												</Typography.Text>
											)}
										</span>
									))}
								</Flex>
							)
						},
						{
							title: 'Projects',
							dataIndex: 'projects',
							key: 'projects'
						},
						{
							title: '',
							key: 'actions',
							render: (_: unknown, plan: CataloguePlan) => (
								<RowActions
									name={plan.name}
									items={actionsFor(plan)}
								/>
							)
						}
					]}
				/>
			)}
			<Modal
				title={
					editing?.create ? 'Add plan' : `Edit plan ${editing?.plan.name ?? ''}`
				}
				open={editing !== null}
				onCancel={() => setEditing(null)}
				onOk={() => form.submit()}
				okText={editing?.create ? 'Add plan' : 'Save'}
				confirmLoading={saving}
				destroyOnHidden
			>
				{editing && (
					<Form<PlanFormValues>
						form={form}
						layout="vertical"
						scrollToFirstError
						initialValues={formValuesOf(editing.plan)}
						onFinish={save}
					>
						{editing.create && (
							<Form.Item
								name="id"
								label="Id"
								extra="Can't be changed later. Lower-case letters, digits and hyphens."
								rules={[
									{ required: true },
									{
										pattern: /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/,
										message:
											'lowercase letters, digits and hyphens; not starting or ending with a hyphen'
									},
									{ max: 40 }
								]}
							>
								<Input
									placeholder="pro"
									autoComplete="off"
								/>
							</Form.Item>
						)}
						<Form.Item
							name="name"
							label="Name"
							rules={[{ required: true, whitespace: true }, { max: 80 }]}
						>
							<Input placeholder="Pro" />
						</Form.Item>
						{LIMIT_ORDER.map((key) => (
							<LimitField
								key={key}
								name={key}
							/>
						))}
						{FEATURE_ORDER.map((key) => (
							<Form.Item
								key={key}
								name={['features', key]}
								label={FEATURE_LABEL[key]}
								valuePropName="checked"
							>
								<Switch />
							</Form.Item>
						))}
					</Form>
				)}
			</Modal>
		</Card>
	);
}

/* One limit: a whole number, or "Unlimited", which stores null and leaves the number unasked. */
function LimitField({ name }: { name: PlanLimitKey }) {
	const form = Form.useFormInstance<PlanFormValues>();
	const unlimited = Form.useWatch(['unlimited', name], form);
	return (
		<Form.Item
			label={LIMIT_LABEL[name]}
			required={!unlimited}
		>
			<Flex
				gap={12}
				align="center"
			>
				<Form.Item
					name={['limits', name]}
					noStyle
					messageVariables={{ label: LIMIT_LABEL[name] }}
					rules={unlimited ? [] : [{ required: true }]}
				>
					<InputNumber
						min={0}
						step={1}
						precision={0}
						disabled={unlimited}
						style={{ width: 180 }}
					/>
				</Form.Item>
				<Form.Item
					name={['unlimited', name]}
					noStyle
					valuePropName="checked"
				>
					<Checkbox>Unlimited</Checkbox>
				</Form.Item>
			</Flex>
		</Form.Item>
	);
}
