import { t } from 'elysia';

// A partial map of catalog key -> value. Per-field validation against the catalog
// (types, option membership, invariants) happens in the route handler so failures
// return the admin_error shape rather than a generic TypeBox validation error.
export const UpdateSettingsBody = t.Record(t.String(), t.Unknown());
