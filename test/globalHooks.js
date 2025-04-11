import { after, before } from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';

before(async () => {
	globalThis.server = createServer().listen(0, '::');
	await once(globalThis.server, 'listening');
});

after(async () => {
	globalThis.server.close();
});
