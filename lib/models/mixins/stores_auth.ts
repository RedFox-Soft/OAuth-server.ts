import { Type as t } from '@sinclair/typebox';

export const authPayloadModel = t.Object({
	accountId: t.Optional(t.String()),
	acr: t.Optional(t.String()),
	amr: t.Optional(t.Array(t.String())),
	authTime: t.Optional(t.Number()),
	claims: t.Optional(t.Object({})),
	nonce: t.Optional(t.String()),
	// One resource is stored as itself, several as the list (process_response_types, device, CIBA).
	resource: t.Optional(t.Union([t.String(), t.Array(t.String())])),
	scope: t.Optional(t.String()),
	sid: t.Optional(t.String())
});
