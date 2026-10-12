import { useEffect } from 'react';
import {
	Button,
	Card,
	Descriptions,
	Flex,
	Form,
	Input,
	Typography
} from 'antd';
import type { EndUserProfile } from '../../../../adapters/types.js';
import { profileClaims } from '../../../../consts/profile_claims.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { usersApi, type EndUser } from './endUser.js';

type Profile = NonNullable<EndUser['profile']>;

interface ProfileValues {
	givenName?: string;
	familyName?: string;
	middleName?: string;
	formatted?: string;
	displayName?: string;
	nickName?: string;
	locale?: string;
	timezone?: string;
	phone?: string;
}

/*
 * Each field, the claim it reaches applications as, and the scope an application asks for to receive it
 * (lib/consts/profile_claims.ts, and the claims-to-scopes table in lib/configs/application.ts). The console keeps
 * its own copy of the labels only; which claims a profile produces is read from the server's own function.
 */
const FIELDS: {
	key: keyof ProfileValues;
	label: string;
	claim: string;
	scope: string;
	placeholder?: string;
}[] = [
	{
		key: 'givenName',
		label: 'Given name',
		claim: 'given_name',
		scope: 'profile'
	},
	{
		key: 'familyName',
		label: 'Family name',
		claim: 'family_name',
		scope: 'profile'
	},
	{
		key: 'middleName',
		label: 'Middle name',
		claim: 'middle_name',
		scope: 'profile'
	},
	{ key: 'formatted', label: 'Full name', claim: 'name', scope: 'profile' },
	{
		key: 'displayName',
		label: 'Display name',
		claim: 'name, when Full name is empty',
		scope: 'profile'
	},
	{ key: 'nickName', label: 'Nickname', claim: 'nickname', scope: 'profile' },
	{
		key: 'locale',
		label: 'Locale',
		claim: 'locale',
		scope: 'profile',
		placeholder: 'en-GB'
	},
	{
		key: 'timezone',
		label: 'Time zone',
		claim: 'zoneinfo',
		scope: 'profile',
		placeholder: 'Europe/London'
	},
	{
		key: 'phone',
		label: 'Phone',
		claim: 'phone_number',
		scope: 'phone',
		placeholder: '+447700900123'
	}
];

function primaryPhone(profile: Profile | undefined): string | undefined {
	const numbers = profile?.phoneNumbers ?? [];
	return (
		numbers.find((p) => p.primary)?.value ??
		(numbers.length === 1 ? numbers[0]?.value : undefined)
	);
}

function valuesOf(profile: Profile | undefined): ProfileValues {
	return {
		givenName: profile?.name?.givenName,
		familyName: profile?.name?.familyName,
		middleName: profile?.name?.middleName,
		formatted: profile?.name?.formatted,
		displayName: profile?.displayName,
		nickName: profile?.nickName,
		locale: profile?.locale,
		timezone: profile?.timezone,
		phone: primaryPhone(profile)
	};
}

const blank = (v: string | undefined) => {
	const t = v?.trim();
	return t ? t : undefined;
};

/*
 * The edited fields over the stored profile, never instead of it: the server replaces the whole profile, and
 * fields this card does not show (a title, other addresses) must survive an edit of the ones it does.
 */
function profileFrom(
	stored: Profile | undefined,
	v: ProfileValues
): EndUserProfile {
	const name = {
		...stored?.name,
		givenName: blank(v.givenName),
		familyName: blank(v.familyName),
		middleName: blank(v.middleName),
		formatted: blank(v.formatted)
	};
	const others = (stored?.phoneNumbers ?? []).filter(
		(p) => p.value !== primaryPhone(stored)
	);
	const phone = blank(v.phone);
	const profile: EndUserProfile = {
		...stored,
		name: Object.values(name).some((x) => x !== undefined) ? name : undefined,
		displayName: blank(v.displayName),
		nickName: blank(v.nickName),
		locale: blank(v.locale),
		timezone: blank(v.timezone),
		phoneNumbers: phone
			? [
					{ value: phone, primary: true },
					...others.map((p) => ({ ...p, primary: false }))
				]
			: others.length
				? others
				: undefined
	};
	// JSON drops undefined members anyway; removing them keeps the request what it says it is.
	return JSON.parse(JSON.stringify(profile)) as EndUserProfile;
}

/* The claims the profile sets, so the claims card can say which of its own entries it overrides. */
export function profileSetClaims(user: EndUser): Set<string> {
	const claims = profileClaims({ profile: user.profile });
	return new Set(Object.keys(claims));
}

/*
 * The person's profile (specs/089 US4): editable for someone this console manages, read-only for a directory's
 * person, whose profile the directory keeps. Every field says what it becomes in a token, because that is the
 * only reason anyone fills it in.
 */
export function ProfileCard({
	bucketId,
	user,
	editable,
	managedBy,
	onChanged
}: {
	bucketId: string;
	user: EndUser;
	editable: boolean;
	managedBy: string | null;
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const [form] = Form.useForm<ProfileValues>();
	const initial = valuesOf(user.profile);

	useEffect(() => {
		form.setFieldsValue(valuesOf(user.profile));
	}, [form, user.profile]);

	async function onSave(values: ProfileValues) {
		// A refusal from the last save is the server's, not a form rule, so nothing clears it but this.
		form.setFields(FIELDS.map((f) => ({ name: f.key, errors: [] })));
		const result = await request('PATCH', usersApi(bucketId, user._id), {
			profile: profileFrom(user.profile, values)
		});
		if (!result.ok) {
			// The server names `profile.locale` and the like; the form's fields drop the prefix.
			const field = result.error.field?.replace(/^profile\./, '');
			const known = FIELDS.find(
				(f) =>
					f.key === field || (field === 'phoneNumbers' && f.key === 'phone')
			);
			if (known) {
				form.setFields([{ name: known.key, errors: [result.error.message] }]);
				return;
			}
			feedback.failed(result);
			return;
		}
		feedback.done('Profile saved.');
		onChanged();
	}

	const hint = (f: (typeof FIELDS)[number]) => (
		<Typography.Text type="secondary">
			→ <code>{f.claim}</code> (scope <code>{f.scope}</code>)
		</Typography.Text>
	);

	if (!editable) {
		const shown = FIELDS.filter((f) => initial[f.key]);
		return (
			<Card
				title="Profile"
				extra={
					managedBy ? (
						<Typography.Text type="secondary">
							Maintained by {managedBy}
						</Typography.Text>
					) : undefined
				}
			>
				{shown.length === 0 ? (
					<Typography.Text type="secondary">No profile.</Typography.Text>
				) : (
					<Descriptions
						column={1}
						size="small"
						items={shown.map((f) => ({
							key: f.key,
							label: f.label,
							children: (
								<Flex
									gap={8}
									wrap
								>
									<span>{initial[f.key]}</span>
									{hint(f)}
								</Flex>
							)
						}))}
					/>
				)}
			</Card>
		);
	}

	return (
		<Card title="Profile">
			<Typography.Paragraph type="secondary">
				Applications receive these as standard claims when they ask for the
				scope shown.
			</Typography.Paragraph>
			<Form<ProfileValues>
				form={form}
				layout="vertical"
				initialValues={initial}
				onFinish={(values) => void onSave(values)}
				style={{ maxWidth: 560 }}
			>
				{FIELDS.map((f) => (
					<Form.Item
						key={f.key}
						name={f.key}
						label={f.label}
						extra={hint(f)}
					>
						<Input
							autoComplete="off"
							placeholder={f.placeholder}
							maxLength={f.key === 'formatted' ? 2048 : 256}
						/>
					</Form.Item>
				))}
				<Flex gap={8}>
					<Button
						type="primary"
						htmlType="submit"
					>
						Save profile
					</Button>
					<Button onClick={() => form.setFieldsValue(valuesOf(user.profile))}>
						Reset
					</Button>
				</Flex>
			</Form>
		</Card>
	);
}
