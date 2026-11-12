import { useState, type ReactNode } from 'react';
import { Button, Flex, Typography } from 'antd';
import type {
	Condition,
	ConditionKind
} from '../../../../behind_proxy/conditions.js';
import { ConditionsEditor } from '../behind-proxy/ConditionsEditor.js';
import { conditionText } from '../behind-proxy/conditionsText.js';

/* What one tool row may add to the API's own conditions (specs/131 research R1), in decision order. */
export const ROW_KINDS: readonly ConditionKind[] = ['group', 'network', 'time'];

/*
 * A tool row's conditions, as a form field: a summary on the row, and the editor under it when opened. The honesty
 * text is always beside the editor (spec User Story 8): an administrator who believes a tool condition stops a thief
 * has a wrong picture of their security.
 */
export function ToolRowConditions({
	value = [],
	onChange,
	inherited,
	timeZone,
	onTimeZone,
	groups,
	countUrl,
	networkFactsOn,
	unavailable,
	nameOf,
	disabled = false
}: {
	value?: Condition[];
	onChange?: (conditions: Condition[]) => void;
	/* The API's own conditions, shown above the row's and not removable here. */
	inherited: { from: string; text: string }[];
	timeZone: string | null;
	onTimeZone: (zone: string | null) => void;
	groups: { id: string; displayName: string }[];
	countUrl: string;
	networkFactsOn: boolean;
	unavailable: Partial<Record<ConditionKind, ReactNode>>;
	nameOf: (groupId: string) => string | null;
	/* Read-only: the summary still says what the row holds. */
	disabled?: boolean;
}) {
	const [open, setOpen] = useState(false);
	const summary = value.map((c) => conditionText(c, nameOf)).join('; ');
	return (
		<Flex
			vertical
			gap={8}
		>
			<Flex
				gap={8}
				align="baseline"
				wrap
			>
				<Typography.Text type="secondary">
					{value.length > 0 ? `Only ${summary}` : 'No conditions of its own'}
				</Typography.Text>
				<Button
					type="link"
					size="small"
					onClick={() => setOpen((was) => !was)}
				>
					{open
						? 'Done'
						: value.length > 0
							? 'Change conditions'
							: 'Add conditions'}
				</Button>
			</Flex>
			{open && (
				<Flex
					vertical
					gap={8}
					style={{ paddingLeft: 16 }}
				>
					<ConditionsEditor
						conditions={value}
						kinds={ROW_KINDS}
						inherited={inherited}
						timeZone={timeZone}
						onTimeZone={onTimeZone}
						groups={groups}
						countUrl={countUrl}
						disabled={disabled}
						networkFactsOn={networkFactsOn}
						unavailable={unavailable}
						onChange={(next) => onChange?.(next)}
					/>
					<Typography.Text type="secondary">
						A tool condition stops an app that names the tool it calls honestly.
						A stolen token in an app that lies about the tool is stopped only by
						your MCP server checking the headers against the body, which MCP
						2026-07-28 servers must do. To keep someone out of the whole API,
						use the API&apos;s own conditions or its sign-in requirement.
					</Typography.Text>
				</Flex>
			)}
		</Flex>
	);
}
