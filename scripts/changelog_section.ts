/*
 * Extracts one version's section from a Keep-a-Changelog file, for the release body.
 *
 *   bun scripts/changelog_section.ts 0.1.0 [CHANGELOG.md]
 *
 * Throws when the section is missing, so a tag pushed before the CHANGELOG was updated fails the
 * release job instead of publishing a release with no notes.
 */

export function changelogSection(markdown: string, version: string): string {
	const wanted = version.replace(/^v/, '');
	const lines = markdown.split(/\r?\n/);
	const heading = new RegExp(`^## \\[${escape(wanted)}\\]`);

	const start = lines.findIndex((line) => heading.test(line));
	if (start === -1) {
		throw new Error(`no CHANGELOG section for ${wanted}`);
	}

	let end = lines.length;
	for (let i = start + 1; i < lines.length; i++) {
		const line = lines[i] as string;
		// The next version heading, or the link-reference block at the end of the file.
		if (line.startsWith('## ') || /^\[[^\]]+\]: /.test(line)) {
			end = i;
			break;
		}
	}

	return lines
		.slice(start + 1, end)
		.join('\n')
		.trim();
}

function escape(text: string): string {
	return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

if (import.meta.main) {
	const [version, file = 'CHANGELOG.md'] = process.argv.slice(2);
	if (!version) {
		console.error(
			'usage: bun scripts/changelog_section.ts <version> [CHANGELOG.md]'
		);
		process.exit(2);
	}
	const markdown = await Bun.file(file).text();
	process.stdout.write(`${changelogSection(markdown, version)}\n`);
}
