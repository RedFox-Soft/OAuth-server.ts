import { base } from '../helpers/interaction_policy/index.ts';
import { resolve } from './registry.js';
import type { OIDCContext } from '../helpers/oidc_context.ts';
import type { PipelineParams } from '../consts/param_list.ts';

// What the device authorization endpoint records about the device that started the flow.
export function deviceInfo(oidc: OIDCContext) {
	return {
		ip: oidc.ip,
		ua: oidc.get('user-agent')
	};
}

export interface PolicyPrompt {
	name: string;
	requestable?: boolean;
	checks: Array<{ reason: string; check: unknown }>;
	executeChecks(oidc: OIDCContext<PipelineParams>): Promise<{
		name: string;
		details: Record<string, unknown>;
		reasons: string[];
		firstError: { error: string; error_description: string };
	} | null>;
}

// The policy is an array carrying helper methods; helpers/interaction_policy/index.ts builds one.
export interface Policy extends Array<PolicyPrompt> {
	get(name: string): PolicyPrompt | undefined;
	add(prompt: PolicyPrompt, index?: number): void;
	remove(name: string): void;
	clear(): void;
}

// Built on first access rather than at module scope: interaction_policy's login prompt imports
// back from the addon index, so constructing the policy while this module is still evaluating
// would run prompt constructors mid-cycle. Undefined means "not built yet", which is also how
// reset() discards a mutated policy.
let baseline: Policy | undefined;

/*
 * interactionPolicy
 *
 * description: The ordered prompts (and their checks) that decide when an end-user must be sent
 * to an interaction. Overridable through the addon registry like any other behavior.
 *
 * Returns a *stable* instance: one request resolves the policy more than once, and tests mutate
 * a prompt's checks in place and restore them afterwards, so rebuilding per call would make both
 * of those incoherent.
 */
export function interactionPolicy(): Policy {
	baseline ??= base();
	return baseline;
}

// The active policy — a registered override if there is one, otherwise the shipped baseline.
// Callers reaching the policy through lib/addon/index.js get the same resolution.
const active = (): Policy => resolve('interactionPolicy', interactionPolicy)();

/*
 * interactionPolicyControl
 *
 * description: Mutation and restore surface for the policy, mirroring `addons.override` /
 * `addons.reset`. `add`/`get`/`remove` act on the *resolved* policy so they land on an override
 * when one is registered rather than on a shadowed baseline.
 *
 * `reset()` and `addons.reset()` are complementary, not interchangeable: the former discards an
 * in-place mutation of the baseline, the latter drops a registered override. The central test
 * teardown calls both.
 */
export const interactionPolicyControl = {
	get(name: string) {
		return active().get(name);
	},
	add(prompt: PolicyPrompt, index?: number) {
		if (index === undefined) active().add(prompt);
		else active().add(prompt, index);
	},
	remove(name: string) {
		active().remove(name);
	},
	reset() {
		baseline = undefined;
	}
};

/*
 * supportedPrompts
 *
 * description: The `prompt` parameter values the server accepts, derived from the resolved policy
 * at each use. Deriving on demand (rather than snapshotting at provider initialisation) is what
 * lets a prompt added after boot be both iterated by the decision path and accepted as a
 * requested value — otherwise the request check would reject the very prompt the policy acts on.
 */
export function supportedPrompts() {
	const prompts = new Set(['none']);
	for (const { name, requestable } of active()) {
		if (requestable) prompts.add(name);
	}
	return prompts;
}
