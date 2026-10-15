import { useEffect, useState } from 'react';
import { Alert, Card, Descriptions, Flex, Select, Typography } from 'antd';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import {
	FEATURE_LABEL,
	FEATURE_ORDER,
	countText,
	limitText,
	warningSentence,
	type PlanView
} from '../planText.js';

/* "8 / 10 applications"; with no limit, the use alone beside "Unlimited". */
function used(count: number | null, max: number | null, unit: string): string {
	if (max === null) {
		return count === null
			? 'Unlimited'
			: `${countText(count)} ${unit} · Unlimited`;
	}
	return count === null
		? `Up to ${countText(max)} ${unit}`
		: `${countText(count)} / ${countText(max)} ${unit}`;
}

/*
 * A project's plan on its Overview (specs/102): each limit beside what the project uses of it, a warning at 80% and
 * at 100% so nobody meets a limit first as a refusal, and what the plan includes. A super administrator moves the
 * project to another plan here; the select is the plan in force until the move is confirmed and saved.
 */
export function BucketPlanCard({
	bucketId,
	bucketName,
	plan,
	canSetPlan,
	onChanged
}: {
	bucketId: string;
	bucketName: string;
	plan: PlanView;
	canSetPlan: boolean;
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [plans, setPlans] = useState<{ id: string; name: string }[] | null>(
		null
	);
	const [saving, setSaving] = useState(false);

	useEffect(() => {
		if (!canSetPlan) return;
		let live = true;
		void request<{ plans: { id: string; name: string }[] }>(
			'GET',
			'/admin/api/plans'
		).then((result) => {
			if (live && result.ok) setPlans(result.data.plans);
		});
		return () => {
			live = false;
		};
	}, [canSetPlan]);

	async function change(planId: string) {
		const next = plans?.find((p) => p.id === planId);
		if (!next || planId === plan.id) return;
		const agreed = await confirm('bucket.plan.change', {
			target: bucketName,
			consequences: [
				`It moves from the ${plan.name} plan to the ${next.name} plan.`,
				'The new limits apply to what is created next; nothing that exists is switched off.'
			]
		});
		if (!agreed) return;
		setSaving(true);
		try {
			const result = await request(
				'PUT',
				`/admin/api/projects/${encodeURIComponent(bucketId)}/plan`,
				{ planId }
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(`${bucketName} is now on the ${next.name} plan.`);
			onChanged();
		} finally {
			setSaving(false);
		}
	}

	return (
		<Card
			title={`Plan: ${plan.name}`}
			extra={
				canSetPlan && plans ? (
					<Select
						aria-label="Plan"
						size="small"
						style={{ minWidth: 160 }}
						value={plan.id}
						loading={saving}
						disabled={saving}
						options={plans.map((p) => ({ value: p.id, label: p.name }))}
						onChange={(value: string) => void change(value)}
					/>
				) : null
			}
		>
			<Flex
				vertical
				gap={12}
			>
				{plan.warnings.map((warning) => (
					<Alert
						key={warning.limit}
						type={warning.level === 'reached' ? 'error' : 'warning'}
						showIcon
						title={warningSentence(warning, plan)}
					/>
				))}
				<Descriptions
					column={1}
					size="small"
					items={[
						{
							key: 'monthlyActiveUsers',
							label: 'Monthly active users',
							children: used(
								plan.usage.monthlyActiveUsers,
								plan.limits.monthlyActiveUsers,
								'monthly active users'
							)
						},
						{
							key: 'applications',
							label: 'Applications',
							children: used(
								plan.usage.applications,
								plan.limits.applicationsPerProject,
								'applications'
							)
						},
						{
							key: 'apis',
							label: 'APIs',
							children: used(
								plan.usage.apis,
								plan.limits.apisPerProject,
								'APIs'
							)
						},
						{
							key: 'projects',
							label: 'Projects per administrator',
							children: limitText(plan.limits.projectsPerAdministrator)
						},
						...FEATURE_ORDER.map((key) => ({
							key,
							label: FEATURE_LABEL[key],
							children: plan.features[key] ? (
								'Included'
							) : (
								<Typography.Text type="secondary">
									Not included on this plan
								</Typography.Text>
							)
						}))
					]}
				/>
			</Flex>
		</Card>
	);
}
