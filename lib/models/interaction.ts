import epochTime from '../helpers/epoch_time.js';
import { BaseModel } from './base_model.js';

export class Interaction extends BaseModel {
	constructor(jti: string, payload: Record<string, unknown>) {
		if (arguments.length === 2) {
			if (payload.session instanceof BaseModel) {
				const { session } = payload;
				Object.assign(
					payload,
					session.payload.accountId
						? {
								session: {
									accountId: session.payload.accountId,
									...(session.payload.uid
										? { uid: session.payload.uid }
										: undefined),
									...(session.payload.jti
										? { cookie: session.payload.jti }
										: undefined),
									...(session.payload.acr
										? { acr: session.payload.acr }
										: undefined),
									...(session.payload.amr
										? { amr: session.payload.amr }
										: undefined)
								}
							}
						: { session: undefined }
				);
			}

			if (payload.grant instanceof BaseModel) {
				const { grant } = payload;
				if (grant.id) {
					Object.assign(payload, { grantId: grant.id });
				}
			}

			super({ jti, ...payload });
		} else {
			super(jti);
		}
	}

	get uid() {
		return this.jti;
	}

	set uid(value) {
		this.jti = value;
	}

	async save(ttl: number) {
		if (typeof ttl !== 'number') {
			throw new TypeError('"ttl" argument must be a number');
		}
		return super.save(ttl);
	}

	async persist() {
		if (typeof this.exp !== 'number') {
			throw new TypeError(
				'persist can only be called on previously persisted Interactions'
			);
		}
		return this.save(this.exp - epochTime());
	}

	static get IN_PAYLOAD() {
		return [
			...super.IN_PAYLOAD,
			'cookieID',
			'session',
			'params',
			'prompt',
			'result',
			'returnTo',
			'trusted',
			'grantId',
			'lastSubmission',
			'deviceCode',
			'cid',
			'parJti'
		];
	}
}
