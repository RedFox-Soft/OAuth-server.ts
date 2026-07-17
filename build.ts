import type { BunPlugin } from 'bun';

// @ant-design/icons' ESM build imports each icon definition from the CJS path
// `@ant-design/icons-svg/lib/asn/*`. Bun's CJS→ESM interop wraps that default
// export as `{ default: iconDef }`, so AntdIcon receives `{default:{...}}` and
// renders nothing ("icon should be icon definiton, but got [object Object]").
// Redirect those imports to the pure-ESM `es/asn/*` files, which use a real
// `export default`, so the default import resolves to the icon definition.
const antdIconsSvgEsm: BunPlugin = {
	name: 'antd-icons-svg-esm',
	setup(build) {
		build.onResolve({ filter: /@ant-design\/icons-svg\/lib\// }, (args) => ({
			path: Bun.resolveSync(
				args.path.replace('/lib/', '/es/'),
				args.resolveDir
			)
		}));
	}
};

const targets: Array<{ entry: string; name: string }> = [
	{ entry: './lib/interactions/loginClient.tsx', name: 'loginClient.[ext]' },
	{ entry: './lib/admin/ui/adminClient.tsx', name: 'admin.[ext]' }
];

async function buildAll() {
	for (const { entry, name } of targets) {
		const result = await Bun.build({
			entrypoints: [entry],
			outdir: './public',
			naming: name,
			minify: true,
			plugins: [antdIconsSvgEsm]
		});
		if (!result.success) {
			for (const log of result.logs) console.error(log);
			throw new AggregateError(result.logs, `build failed: ${entry}`);
		}
		console.log(`built ${entry} → public/${name.replace('[ext]', 'js')}`);
	}
}

await buildAll();

if (process.argv.includes('--watch')) {
	const { watch } = await import('node:fs');
	let timer: ReturnType<typeof setTimeout> | null = null;
	console.log('watching lib/ for changes…');
	watch('./lib', { recursive: true }, () => {
		if (timer) clearTimeout(timer);
		timer = setTimeout(() => {
			buildAll().catch((err) => console.error(err));
		}, 150);
	});
}
