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
			'MongoDB connection string, and the setting that selects MongoDB as the datastore. Required when MongoDB is the chosen backend; leave it unset to run on PostgreSQL. Setting it together with `POSTGRES_URL` is refused at startup — a deployment uses exactly one datastore, and silently preferring one of two configured databases is indistinguishable from total data loss. Not read when NODE_ENV is `test`, where the in-memory adapter is used instead.',
		example: 'mongodb://localhost:27017'
	},
	{
		name: 'DATABASE_NAME',
		requirement: 'required',
		description:
			'Name of the MongoDB database holding every collection. Required alongside `MONGODB_URI`; PostgreSQL takes its database name from the connection URL instead, so this is unused there. Not read when NODE_ENV is `test`.',
		example: 'OAuth'
	},
	{
		name: 'POSTGRES_URL',
		requirement: 'optional',
		description:
			'PostgreSQL connection string, and the setting that selects PostgreSQL as the datastore instead of MongoDB. The database name is part of the URL, so `DATABASE_NAME` is not used. Setting it together with `MONGODB_URI` is refused at startup. Named `POSTGRES_URL` rather than the conventional `DATABASE_URL` deliberately: a name that generic is eventually set by something else in a container, and it would then select a backend nobody chose.',
		example: 'postgres://user:password@localhost:5432/oauth'
	},
	{
		name: 'KEYRING',
		requirement: 'optional',
		description:
			'The instance keyring: the keys secrets stored in the database are encrypted with (client secrets, sign-in provider credentials, the SMTP password, private signing keys, authenticator secrets). A deployment secret like the connection string, never kept in the database it protects; store it in a secrets manager and back it up apart from the database. Generate one with `bun run keyring new`, or let first-run setup generate it. Supplying it here and through a keyring file at once is refused at startup. Without a keyring, secrets are stored unencrypted and the console says so. Not read when NODE_ENV is `test`.',
		example: '{"v":1,"write":"20261029-ab12","keys":{"20261029-ab12":"…"}}'
	},
	{
		name: 'KEYRING_FILE',
		requirement: 'optional',
		description:
			'Where the keyring file is, when the keyring is supplied as a file (a mounted secret, a volume) rather than through `KEYRING`. Defaults to `keyring/foxauth.keyring` under the working directory (`/app/keyring/foxauth.keyring` in the image). First-run setup writes a generated keyring here only when the directory already exists, so a container without a volume never keeps a key it would lose. Under NODE_ENV `test` the default is a directory nobody creates, so a spec never writes into a working copy.',
		example: '/run/secrets/foxauth.keyring'
	},
	{
		name: 'NODE_ENV',
		requirement: 'optional',
		description:
			'`test` selects the in-memory storage adapter and the capturing mail transport, and disables outbound Sentry delivery. Any other value is reported to Sentry as the environment label; the Docker image sets `production`.',
		example: 'production'
	}
];
