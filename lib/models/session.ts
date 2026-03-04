import { Type as t, type Static } from '@sinclair/typebox';
import nanoid from '../helpers/nanoid.js';
import epochTime from '../helpers/epoch_time.js';

import { cookieNames } from '../consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { BaseModel, BaseModelPayload } from './base_model.js';

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
	#isNew = false;

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

	async save(ttl: number) {
		if (typeof ttl !== 'number') {
			throw new TypeError('"ttl" argument must be a number');
		}
		// one by one adapter ops to allow for uid to have a unique index
		if (this.oldId) {
			await this.adapter.destroy(this.oldId);
		}

		const result = await super.save(ttl);

		this.touched = false;

		return result;
	}

	async persist() {
		if (typeof this.payload.exp !== 'number') {
			throw new TypeError(
				'persist can only be called on previously persisted Sessions'
			);
		}
		return this.save(this.payload.exp - epochTime());
	}

	async destroy() {
		await super.destroy();
		this.destroyed = true;
	}

	resetIdentifier() {
		this.oldId = this.id;
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

	authorizationFor(clientId) {
		// the call will not set, let's not modify the session object
		if (arguments.length === 1 && !this.payload.authorizations) {
			return {};
		}

		this.payload.authorizations = this.payload.authorizations || {};
		if (!this.payload.authorizations[clientId]) {
			this.payload.authorizations[clientId] = {};
		}

		return this.payload.authorizations[clientId];
	}

	sidFor(clientId, value) {
		const authorization = this.authorizationFor(...arguments);

		if (value) {
			authorization.sid = value;
			return undefined;
		}

		return authorization.sid;
	}

	grantIdFor(clientId, value) {
		const authorization = this.authorizationFor(...arguments);

		if (value) {
			authorization.grantId = value;
			return undefined;
		}

		return authorization.grantId;
	}

	ensureClientContainer(clientId) {
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

		Object.assign(
			this,
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
