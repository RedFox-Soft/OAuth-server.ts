import { useEffect, useState } from 'react';
import { Form, Select } from 'antd';
import { scopeOptionLabel, type ScopeOption } from '../pages/ScopeSwitcher.js';
import { request } from './request.js';

/*
 * The team a new project will belong to, chosen in the creation dialog (specs/087). Created in the
 * wrong team, a thing has to be moved, which is a previewed act; chosen here, it costs a click. The header's
 * current team is the default, so a dialog left alone creates exactly where it did before.
 *
 * Offered from the scope list — the teams the caller works in — and checked again by the server, which refuses
 * a team the caller may not create in.
 */
export function GroupField() {
	const form = Form.useFormInstance<{ teamId?: string }>();
	const [groups, setGroups] = useState<ScopeOption[] | null>(null);

	useEffect(() => {
		void (async () => {
			const result = await request<{
				activeTeamId: string;
				available: ScopeOption[];
			}>('GET', '/admin/api/scope');
			if (!result.ok) {
				setGroups([]);
				return;
			}
			setGroups(result.data.available);
			if (form.getFieldValue('teamId') === undefined) {
				form.setFieldValue('teamId', result.data.activeTeamId);
			}
		})();
	}, [form]);

	return (
		<Form.Item
			name="teamId"
			label="Team"
			extra="Its members manage it. You can move it to another team later."
			rules={[{ required: true, message: 'Choose a team' }]}
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
