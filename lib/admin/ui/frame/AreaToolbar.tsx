import type { ReactNode } from 'react';
import { Flex, Input, Space } from 'antd';
import { SearchOutlined } from '@ant-design/icons';

/*
 * The strip above a list: what narrows it on the left, the way to add to it on the right. The same
 * places on every list, so "New …" is never hunted for.
 */
export function AreaToolbar({
	search,
	onSearch,
	searchPlaceholder = 'Search',
	filters,
	create
}: {
	search?: string;
	onSearch?: (value: string) => void;
	searchPlaceholder?: string;
	filters?: ReactNode;
	/* Shown only when the caller may create; pass nothing otherwise. */
	create?: ReactNode;
}) {
	return (
		<Flex
			justify="space-between"
			align="center"
			wrap
			gap={12}
			style={{ marginBottom: 16 }}
		>
			<Space wrap>
				{onSearch && (
					<Input
						allowClear
						prefix={<SearchOutlined />}
						placeholder={searchPlaceholder}
						value={search}
						onChange={(event) => onSearch(event.target.value)}
						style={{ width: 280, maxWidth: '100%' }}
					/>
				)}
				{filters}
			</Space>
			{create}
		</Flex>
	);
}
