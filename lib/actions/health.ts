import { Elysia } from 'elysia';
import { HealthResponse } from 'lib/shared/response_schemas.js';

export const healthCheck = new Elysia().get(
	'/health',
	() => ({
		status: 'OK',
		timestamp: new Date().toISOString()
	}),
	{
		response: { 200: HealthResponse }
	}
);
