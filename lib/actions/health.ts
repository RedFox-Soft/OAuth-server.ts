import { Elysia } from 'elysia';

export const healthCheck = new Elysia().get('/health', () => ({
	status: 'OK',
	timestamp: new Date().toISOString()
}));
