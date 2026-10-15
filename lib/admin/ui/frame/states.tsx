import type { ReactNode } from 'react';
import { Button, Empty, Result } from 'antd';
import { Link } from './router.js';

/*
 * The states every screen can be in besides "showing its data", drawn the same way everywhere. A failed
 * load is never an empty table: "nothing here" and "could not find out" are different answers, and
 * showing the first for the second is how an operator concludes a bucket has no keys.
 */

export function NotFound({
	backHref,
	backLabel
}: {
	backHref?: string;
	backLabel?: string;
}) {
	return (
		<Result
			status="404"
			title="Page not found"
			subTitle="There is nothing at this address in the console."
			extra={
				<Link href={backHref ?? '/admin/projects'}>
					{backLabel ?? 'Go to Projects'}
				</Link>
			}
		/>
	);
}

export function NoAccess({
	what,
	backHref,
	backLabel
}: {
	what: string;
	backHref: string;
	backLabel: string;
}) {
	return (
		<Result
			status="403"
			title={`You cannot open this ${what}`}
			subTitle={`It does not exist, or it belongs to a team you are not in.`}
			extra={<Link href={backHref}>{backLabel}</Link>}
		/>
	);
}

export function InstanceOnly() {
	return (
		<Result
			status="403"
			title="Only an instance administrator can open this page"
			extra={<Link href="/admin/projects">Go to Projects</Link>}
		/>
	);
}

export function LoadFailed({
	reason,
	onRetry
}: {
	reason?: string;
	onRetry: () => void;
}) {
	return (
		<Result
			status="warning"
			title="This could not be loaded"
			subTitle={reason ?? 'The server did not answer. Try again in a moment.'}
			extra={
				<Button
					type="primary"
					onClick={onRetry}
				>
					Retry
				</Button>
			}
		/>
	);
}

/* "Nothing yet": what belongs here, and the way to create the first one when the caller may. */
export function EmptyState({
	purpose,
	create
}: {
	purpose: string;
	create?: ReactNode;
}) {
	return (
		<Empty
			image={Empty.PRESENTED_IMAGE_SIMPLE}
			description={purpose}
		>
			{create}
		</Empty>
	);
}

/* "No match": the list is not empty, the search is too narrow. Never offers to create. */
export function NoMatch({
	query,
	onClear,
	clearLabel = 'Clear search'
}: {
	query: string;
	onClear: () => void;
	clearLabel?: string;
}) {
	return (
		<Empty
			image={Empty.PRESENTED_IMAGE_SIMPLE}
			description={`Nothing matches “${query}”.`}
		>
			<Button onClick={onClear}>{clearLabel}</Button>
		</Empty>
	);
}
