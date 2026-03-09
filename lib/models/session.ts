import { Type as t, type Static } from '@sinclair/typebox';
import nanoid from '../helpers/nanoid.js';
import epochTime from '../helpers/epoch_time.js';

import { cookieNames } from '../consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { BaseModel, BaseModelPayload } from './base_model.js';
import { ttl } from 'lib/configs/liveTime.js';

const SessionPayload = t.Composite([
	BaseModelPayload,
	t.Object({
		uid: t.String(),
		accountId: t.Optional(t.String()),
		loginTs: t.Optional(t.Number()),
		amr: t.Optional(t.Array(t.String())),
		acr: t.Optional(t.String()),
		transient: t.Optional(t.Boolean()),
		state: t.Optional(t.String()),
		authorizations: t.Optional(
			t.Record(
				t.String(),
				t.Object({
					sid: t.Optional(t.String()),
					grantId: t.Optional(t.String())
				})
			)
		)
	})
]);
type SessionPayloadType = Static<typeof SessionPayload>;

function sessionPayload(
	payload: Partial<SessionPayloadType> = {}
): SessionPayloadType {
	payload.uid ||= nanoid();
	payload.jti ||= nanoid();
	return payload as SessionPayloadType;
}

export class Session extends BaseModel<SessionPayloadType> {
	model = SessionPayload;
	#isDestroyed = false;
	#isNew = true;
	#oldId: string | undefined;
	touched = false;

	constructor(payload?: Partial<SessionPayloadType>) {
		super(sessionPayload(payload));
		this.#isNew = !payload;
	}

	get isNew() {
		return this.#isNew;
	}

	static async findByUid(uid: string) {
		const stored = await this.adapter.findByUid(uid);
		if (!stored) {
			return;
		}
		try {
			const payload = await this.verify(stored);
			return new this(payload);
		} catch (err) {
			return;
		}
	}

	static async get(ctx) {
		// is there supposed to be a session bound? generate if not
		const cookieSessionId = ctx.cookie[cookieNames.session]?.value;

		let session;

		if (cookieSessionId) {
			session = await this.find(cookieSessionId);
			// underlying session was removed since we have a session id in cookie, let's assign an
			// empty data so that session.new is not true and cookie will get written even if nothing
			// gets written to it
			session ||= new this({});
		} else {
			session = new this();
		}

		if (ctx.oidc instanceof OIDCContext) {
			ctx.oidc.entity('Session', session);
		}

		return session;
	}

	async save() {
		if (this.#isDestroyed) {
			return this.id;
		}
		// one by one adapter ops to allow for uid to have a unique index
		if (this.#oldId) {
			await this.adapter.destroy(this.#oldId);
			this.#oldId = undefined;
		}

		const result = await super.save(ttl.Session);
		this.touched = false;
		return result;
	}

	async destroy() {
		await super.destroy();
		this.#isDestroyed = true;
	}

	resetIdentifier() {
		this.#oldId = this.id;
		this.id = nanoid();
		this.touched = true;
	}

	authTime() {
		return this.payload.loginTs;
	}

	past(age: number | string) {
		const maxAge = +age;

		if (this.payload.loginTs) {
			return epochTime() - this.payload.loginTs > maxAge;
		}

		return true;
	}

	authorizationFor(clientId: string) {
		this.payload.authorizations ||= {};
		this.payload.authorizations[clientId] ||= {};

		return this.payload.authorizations[clientId];
	}

	sidFor(clientId: string, value?: string) {
		if (value) {
			const authorization = this.authorizationFor(clientId);
			authorization.sid = value;
			return;
		}

		return this.payload.authorizations?.[clientId]?.sid;
	}

	grantIdFor(clientId: string, value?: string) {
		if (value) {
			const authorization = this.authorizationFor(clientId);
			authorization.grantId = value;
			return;
		}

		return this.payload.authorizations?.[clientId]?.grantId;
	}

	ensureClientContainer(clientId: string) {
		if (!this.sidFor(clientId)) {
			this.sidFor(clientId, nanoid());
		}
	}

	loginAccount(details) {
		const {
			transient = false,
			accountId,
			loginTs = epochTime(),
			amr,
			acr
		} = details;
		if (typeof accountId !== 'string' || !accountId) {
			throw new TypeError(
				`accountId must be a non-empty string, got: ${typeof accountId}`
			);
		}

		Object.assign(
			this.payload,
			{
				accountId,
				loginTs,
				amr,
				acr
			},
			transient ? { transient: true } : undefined
		);
	}
}
