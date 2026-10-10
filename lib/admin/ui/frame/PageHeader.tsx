import type { ReactNode } from 'react';
import { Breadcrumb, Flex, Space, Tabs, Typography } from 'antd';
import { Link, useNavigate } from './router.js';

/*
 * The top of every console screen, the same everywhere: where you are (breadcrumbs that mirror the
 * address), what this is (its name — never "<name> — users"), at most three tags in a fixed order
 * (reserved, state, urgent), and the actions that apply to the whole thing. An entity with several
 * areas gets them as tabs, each an address of its own.
 *
 * In-page Back buttons are gone: the breadcrumb and the browser's Back do that job, and a Back button
 * that is really "go to the list" lies the moment the page was reached from somewhere else.
 */

export interface Crumb {
	label: string;
	href?: string;
}

export interface HeaderTab {
	key: string;
	label: string;
	href: string;
}

export function PageHeader({
	title,
	crumbs,
	tags,
	actions,
	meta,
	description,
	tabs,
	activeTab
}: {
	title: ReactNode;
	crumbs?: Crumb[];
	tags?: ReactNode;
	actions?: ReactNode;
	meta?: ReactNode;
	description?: ReactNode;
	tabs?: HeaderTab[];
	activeTab?: string;
}) {
	const navigate = useNavigate();
	return (
		<Flex
			vertical
			gap={8}
			style={{ marginBottom: 16 }}
		>
			{crumbs && crumbs.length > 0 && (
				<Breadcrumb
					items={crumbs.map((crumb) => ({
						title: crumb.href ? (
							<Link href={crumb.href}>{crumb.label}</Link>
						) : (
							crumb.label
						)
					}))}
				/>
			)}
			<Flex
				justify="space-between"
				align="center"
				wrap
				gap={12}
			>
				<Space
					wrap
					size={8}
				>
					<Typography.Title
						level={3}
						style={{ margin: 0 }}
					>
						{title}
					</Typography.Title>
					{tags}
				</Space>
				{actions && <Space wrap>{actions}</Space>}
			</Flex>
			{meta && <Typography.Text type="secondary">{meta}</Typography.Text>}
			{description && (
				<Typography.Paragraph
					type="secondary"
					style={{ margin: 0 }}
				>
					{description}
				</Typography.Paragraph>
			)}
			{tabs && tabs.length > 0 && (
				<Tabs
					activeKey={activeTab}
					items={tabs.map((tab) => ({ key: tab.key, label: tab.label }))}
					onChange={(key) => {
						const tab = tabs.find((t) => t.key === key);
						if (tab) void navigate(tab.href);
					}}
					style={{ marginBottom: -8 }}
				/>
			)}
		</Flex>
	);
}
