import type { OIDCContext } from '../oidc_context.ts';

export interface CheckPartial<
	T extends Record<string, unknown> = Record<string, unknown>
> {
	reason: string;
	description: string;
	error?: string;
	details?: (oidc: OIDCContext) => Partial<T> | Promise<Partial<T>>;
	check: (oidc: OIDCContext) => boolean | Promise<boolean>;
}

export class Prompt<
	T extends Record<string, unknown> = Record<string, unknown>
> {
	name: string = 'undefined';
	requestable: boolean = false;
	checks: CheckPartial<T>[] = [];
	defaultError = 'interaction_required';

	get requestableCheck(): CheckPartial<T> {
		return {
			reason: `${this.name}_prompt`,
			description: `${this.name} prompt was not resolved`,
			error: `${this.name}_required`,
			check: (oidc) => {
				if (oidc.prompts.has(this.name) && oidc.promptPending(this.name)) {
					return true;
				}

				return false;
			}
		};
	}

	details(_oidc: OIDCContext): Partial<T> | Promise<Partial<T>> {
		return {};
	}

	async executeChecks(oidc: OIDCContext): Promise<{
		name: string;
		details: T;
		reasons: string[];
		firstError: { error: string; error_description: string };
	} | null> {
		const checks = this.requestable
			? [this.requestableCheck, ...this.checks]
			: this.checks;
		type executeResult = Record<string, Partial<T> | undefined>;
		let firstError = null;
		const results: executeResult = {};
		for (const { reason, description, error, details, check } of checks) {
			if (await check(oidc)) {
				firstError ??= {
					error: error || this.defaultError,
					error_description:
						description || 'interaction is required from the end-user'
				};
				results[reason] = await details?.(oidc);
			}
		}
		if (!firstError) {
			return null;
		}

		return {
			name: this.name,
			reasons: Object.keys(results),
			details: Object.assign(
				{},
				await this.details(oidc),
				...Object.values(results)
			),
			firstError
		};
	}
}
