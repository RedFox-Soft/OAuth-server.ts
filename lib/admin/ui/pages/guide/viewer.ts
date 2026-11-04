import {
	GUIDE_FLAG_SETTINGS,
	type GuideFlag
} from '../../../../consts/situation_guide.js';
import type { GuideViewer } from '../../../../situation_guide/availability.js';
import type { BucketCan } from '../../frame/can.js';
import type { BucketSummary } from '../bucketView.js';

const ALL_ON = Object.fromEntries(
	Object.keys(GUIDE_FLAG_SETTINGS).map((flag) => [flag, true])
) as Record<GuideFlag, boolean>;

/* Who is looking, as the guide's buttons need it: built in one place so the guide and the Overview card agree. */
export function guideViewerOf({
	features,
	superAdmin,
	can,
	summary
}: {
	features: Record<GuideFlag, boolean> | undefined;
	superAdmin: boolean;
	can: BucketCan;
	summary: BucketSummary | null;
}): GuideViewer {
	const plan = superAdmin ? null : (summary?.plan ?? null);
	return {
		// A missing statement reads as on: the button then leads to a form the server still checks.
		features: features ?? ALL_ON,
		superAdmin,
		rights: {
			edit: can.edit,
			manageUsers: can.manageUsers,
			changeAddress: can.changeAddress
		},
		// A super administrator reads the plan but is never held to it.
		planFeatures: plan?.features ?? null,
		room: plan
			? {
					plan: plan.name,
					limits: {
						applications: plan.limits.applicationsPerProject,
						apis: plan.limits.apisPerProject,
						connectedServices: plan.limits.connectedServicesPerProject
					},
					usage: {
						applications: plan.usage.applications,
						apis: plan.usage.apis,
						connectedServices: plan.usage.connectedServices
					}
				}
			: null
	};
}
