import { useEffect, useState } from 'react';
import { Form, Select } from 'antd';
import { scopeOptionLabel, type ScopeOption } from '../pages/ScopeSwitcher.js';
import { request } from './request.js';

/*
 * The group a new bucket will belong to, chosen in the creation dialog (specs/087). Created in the
 * wrong group, a thing has to be moved, which is a previewed act; chosen here, it costs a click. The header's
 * current group is the default, so a dialog left alone creates exactly where it did before.
 *
 * Offered from the scope list — the groups the caller works in — and checked again by the server, which refuses
 * a group the caller may not create in.
 */
export function GroupField() {
	const form = Form.useFormInstance<{ groupId?: string }>();
	const [groups, setGroups] = useState<ScopeOption[] | null>(null);

	useEffect(() => {
		void (async () => {
			const result = await request<{
				activeGroupId: string;
				available: ScopeOption[];
			}>('GET', '/admin/api/scope');
			if (!result.ok) {
				setGroups([]);
				return;
			}
			setGroups(result.data.available);
			if (form.getFieldValue('groupId') === undefined) {
				form.setFieldValue('groupId', result.data.activeGroupId);
			}
		})();
	}, [form]);

	return (
		<Form.Item
			name="groupId"
			label="Group"
			extra="Its members manage it. You can move it to another group later."
			rules={[{ required: true, message: 'Choose a group' }]}
		>
			<Select<string>
				loading={groups === null}
				options={(groups ?? []).map((g) => ({
					value: g.id,
					label: scopeOptionLabel(g)
				}))}
			/>
		</Form.Item>
	);
}
