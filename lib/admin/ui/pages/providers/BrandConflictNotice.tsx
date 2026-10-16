import type { CSSProperties } from 'react';
import { Alert, Tag } from 'antd';

/*
 * What a provider's button would look like to people when the project's providers make it confusing (specs/105),
 * in words an administrator can act on. The server decides which provider is affected (`signInWarnings` on the
 * list, `warnings` on a provider); this only says what it means.
 */
export type BrandConflictWarning = 'duplicate_brand' | 'named_like_brand';

const isConflict = (warning: string): warning is BrandConflictWarning =>
	warning === 'duplicate_brand' || warning === 'named_like_brand';

export function brandConflictsIn(warnings: readonly string[] | undefined) {
	return (warnings ?? []).filter(isConflict);
}

/* `name` is the brand for a duplicate and the provider's own name for one named like a brand. */
function wording(warning: BrandConflictWarning, name: string) {
	return warning === 'duplicate_brand'
		? {
				tag: 'Duplicate button',
				title: `Two “Sign in with ${name}” buttons`,
				description: `This project has more than one enabled ${name} connection. Each button must carry ${name}'s own wording, so people can tell them apart only by the small name under each. Turn off the connection you no longer need.`
			}
		: {
				tag: 'Named like a brand',
				title: `This button reads like ${name.trim()} but is not`,
				description: `People will see “Sign in with ${name.trim()}” without ${name.trim()}'s mark, which is what an imitation looks like. If this really is ${name.trim()}, connect it from the list of recognised providers instead; otherwise give it a name of its own.`
			};
}

export function BrandConflictNotice({
	warnings,
	name,
	style
}: {
	warnings: readonly string[] | undefined;
	name: string;
	style?: CSSProperties;
}) {
	return (
		<>
			{brandConflictsIn(warnings).map((warning) => {
				const { title, description } = wording(warning, name);
				return (
					<Alert
						key={warning}
						style={style}
						type="warning"
						showIcon
						title={title}
						description={description}
					/>
				);
			})}
		</>
	);
}

export function BrandConflictTags({
	warnings,
	name
}: {
	warnings: readonly string[] | undefined;
	name: string;
}) {
	return (
		<>
			{brandConflictsIn(warnings).map((warning) => {
				const { tag, title } = wording(warning, name);
				return (
					<Tag
						key={warning}
						color="orange"
						title={title}
					>
						{tag}
					</Tag>
				);
			})}
		</>
	);
}
