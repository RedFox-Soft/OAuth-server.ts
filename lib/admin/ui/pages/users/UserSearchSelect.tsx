import { useEffect, useState } from 'react';
import { Select } from 'antd';
import { request } from '../../frame/request.js';
import { usersApi, type EndUserPage } from './endUser.js';

const SHOWN = 20;

/*
 * Choosing people from a bucket that may hold thousands of them (specs/082): the options are the server's
 * answer to what has been typed — the start of an email or username, or an exact ID — never the whole
 * bucket, which the console no longer reads. The people already chosen keep their labels while the
 * options change under them.
 */
export function UserSearchSelect({
	bucketId,
	value,
	onChange,
	placeholder = 'Find people by email'
}: {
	bucketId: string;
	value: string[];
	onChange: (ids: string[]) => void;
	placeholder?: string;
}) {
	const [text, setText] = useState('');
	const [options, setOptions] = useState<{ label: string; value: string }[]>(
		[]
	);
	const [loading, setLoading] = useState(false);
	// The email of everyone an answer has named, so a chosen person keeps their label when the options change.
	const [labels, setLabels] = useState<ReadonlyMap<string, string>>(new Map());

	useEffect(() => {
		let current = true;
		const timer = setTimeout(() => {
			setLoading(true);
			const params = new URLSearchParams({ count: String(SHOWN) });
			const q = text.trim();
			if (q) params.set('q', q);
			void request<EndUserPage>(
				'GET',
				`${usersApi(bucketId)}?${params.toString()}`
			)
				.then((result) => {
					if (!current || !result.ok) return;
					setLabels((known) => {
						const next = new Map(known);
						for (const user of result.data.users)
							next.set(user._id, user.email);
						return next;
					});
					setOptions(
						result.data.users.map((user) => ({
							label: user.email,
							value: user._id
						}))
					);
				})
				.finally(() => {
					if (current) setLoading(false);
				});
		}, 250);
		return () => {
			current = false;
			clearTimeout(timer);
		};
	}, [bucketId, text]);

	// Chosen people the current answer does not include stay listed, so their tags keep their email.
	const chosen = value
		.filter((id) => !options.some((o) => o.value === id))
		.map((id) => ({ label: labels.get(id) ?? id, value: id }));

	return (
		<Select
			mode="multiple"
			style={{ width: '100%' }}
			placeholder={placeholder}
			value={value}
			onChange={onChange}
			loading={loading}
			showSearch={{ onSearch: setText, filterOption: false }}
			onBlur={() => setText('')}
			options={[...chosen, ...options]}
			notFoundContent={loading ? 'Searching…' : 'Nobody matches'}
		/>
	);
}
