import { ApplicationConfig } from 'lib/configs/application.js';
import { type BaseModel, type BaseModelPayloadType } from '../base_model.js';
import { type BaseToken, type BaseTokenPayloadType } from '../base_token.js';

type PoliciesPayload = BaseTokenPayloadType & { policies?: string[] };

function validate(policies: unknown): void {
	if (!Array.isArray(policies)) {
		throw new TypeError('policies must be an array');
	}
	if (!policies.length) {
		throw new TypeError('policies must not be empty');
	}
	policies.forEach((policy) => {
		if (typeof policy !== 'string') {
			throw new TypeError('policies must be strings');
		}
		if (!ApplicationConfig['registration.policies']?.[policy]) {
			throw new TypeError(`policy ${policy} not configured`);
		}
	});
}

export default function hasPolicies<TPayload extends PoliciesPayload>(
	superclass: typeof BaseToken<TPayload>
) {
	return class extends superclass {
		async save() {
			if (typeof this.payload.policies !== 'undefined') {
				validate(this.payload.policies);
			}
			return super.save();
		}

		static async tryFind<
			A extends BaseModelPayloadType,
			T extends BaseModel<A>
		>(
			this: new (payload: A) => T,
			value: string,
			options?: { ignoreExpiration?: boolean }
		): Promise<T | undefined> {
			const result = await super.tryFind<A, T>(value, options);
			const policies = (result?.payload as PoliciesPayload | undefined)
				?.policies;
			if (typeof policies !== 'undefined') {
				validate(policies);
			}
			return result;
		}
	};
}
