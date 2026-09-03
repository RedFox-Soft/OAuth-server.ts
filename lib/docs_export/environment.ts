export interface EnvironmentVariable {
	readonly name: string;
	readonly requirement: 'required' | 'optional' | 'test-only';
	readonly description: string;
	readonly example?: string;
}

/*
 * Hand-maintained, and pinned against the source by test/docs_export/environment.spec.ts: a variable
 * read anywhere under lib/ must appear here, and an entry here must still be read somewhere.
 */
export const ENVIRONMENT_VARIABLES: readonly EnvironmentVariable[] = [
	{
		name: 'ISSUER',
		requirement: 'required',
		description:
			'Canonical public URL of this authorization server. It is the `iss` of every token, the base of every endpoint advertised in discovery, and the redirect target of the admin console client.',
		example: 'https://auth.example.com'
	},
	{
		name: 'MONGODB_URI',
		requirement: 'required',
		description:
			'MongoDB connection string. Not read when NODE_ENV is `test`, where the in-memory adapter is used instead.',
		example: 'mongodb://localhost:27017'
	},
	{
		name: 'DATABASE_NAME',
		requirement: 'required',
		description:
			'Name of the MongoDB database holding every collection. Not read when NODE_ENV is `test`.',
		example: 'OAuth'
	},
	{
		name: 'NODE_ENV',
		requirement: 'optional',
		description:
			'`test` selects the in-memory storage adapter and the capturing mail transport, and disables outbound Sentry delivery. Any other value is reported to Sentry as the environment label; the Docker image sets `production`.',
		example: 'production'
	}
];
