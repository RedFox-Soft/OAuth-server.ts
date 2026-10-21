import type { FormInstance } from 'antd';
import { Collapse, Form, Input, Select, Switch } from 'antd';
import { grantRefusedToPublicClient } from '../../../../consts/confidential_grants.js';
import {
	AUTH_OPTIONS,
	CIBA_DELIVERY_MODE_OPTIONS,
	CIBA_GRANT_TYPE,
	GRANT_OPTIONS,
	KEY_SWITCHES,
	KEY_TEXT_FIELDS,
	parseJwks,
	type FormValues
} from './clientForm.js';
import { LogoField, OriginsField, PrimaryColorField } from './fields.js';

/*
 * Every setting of an application, as fields of a form the caller owns. One body for the Settings tab and for
 * "Configure everything yourself", so an application has one set of fields wherever it is edited.
 */
export function ClientFormFields({
	form,
	siblings
}: {
	form: FormInstance<FormValues>;
	/* Other applications of the project with browser origins, offered to copy from. */
	siblings: { label: string; origins: string[] }[];
}) {
	return (
		<>
			<Form.Item
				name="clientName"
				label="Name"
			>
				<Input />
			</Form.Item>
			<Form.Item
				name="applicationType"
				label="Application type"
			>
				<Select
					options={[
						{ label: 'web', value: 'web' },
						{ label: 'native', value: 'native' }
					]}
				/>
			</Form.Item>
			<Form.Item
				name="grantTypes"
				label="Grant types"
				dependencies={['tokenEndpointAuthMethod']}
				rules={[
					{ required: true },
					({ getFieldValue }) => ({
						validator(_, grants: string[] | undefined) {
							const refused = grantRefusedToPublicClient(
								getFieldValue('tokenEndpointAuthMethod'),
								grants ?? []
							);
							return refused
								? Promise.reject(
										new Error(
											`${GRANT_OPTIONS.find((option) => option.value === refused)?.label ?? refused} needs a client that authenticates — choose a token endpoint auth method other than none.`
										)
									)
								: Promise.resolve();
						}
					})
				]}
			>
				<Select
					mode="multiple"
					options={GRANT_OPTIONS}
				/>
			</Form.Item>
			<Form.Item
				name="tokenEndpointAuthMethod"
				label="Token endpoint auth"
			>
				<Select options={AUTH_OPTIONS} />
			</Form.Item>
			<Form.Item
				name="redirectUris"
				label="Redirect URIs (one per line)"
			>
				<Input.TextArea
					rows={3}
					placeholder="https://app.example.com/cb"
				/>
			</Form.Item>
			<Form.Item
				name="postLogoutRedirectUris"
				label="Sign-out return URIs (one per line)"
				extra="Where people may be sent back after signing out. Exact match, like the redirect URIs."
			>
				<Input.TextArea
					rows={2}
					placeholder="https://app.example.com"
				/>
			</Form.Item>
			<Form.Item
				name="corsOrigins"
				label="Browser origins"
				extra="Web origins whose browser code may call this application's token and userinfo endpoints. Exact match, no wildcards; an empty list allows none."
			>
				<OriginsField siblings={siblings} />
			</Form.Item>
			<Form.Item
				name="scope"
				label="Scope"
			>
				<Input placeholder="openid profile email" />
			</Form.Item>
			<Form.Item
				name="requireConsent"
				label="Require consent"
				valuePropName="checked"
			>
				<Switch />
			</Form.Item>
			{/* With consent skipped there is no page to choose on, so the switch would mean nothing. */}
			<Form.Item<FormValues>
				shouldUpdate={(prev, cur) => prev.requireConsent !== cur.requireConsent}
				noStyle
			>
				{() =>
					form.getFieldValue('requireConsent') ? (
						<Form.Item
							name="partialConsent"
							label="Lets people choose permissions"
							valuePropName="checked"
							extra="People can untick individual permissions on the consent page. Turn on only if this application works with fewer permissions than it asks for."
						>
							<Switch />
						</Form.Item>
					) : null
				}
			</Form.Item>
			<Form.Item
				name="logo"
				label="Logo on the consent page"
				extra="Shown only to people who sign in through this organization’s own project. PNG, JPEG or WebP, up to 64 KiB; square, at least 128 px."
			>
				<LogoField />
			</Form.Item>
			<Form.Item
				name="primaryColor"
				label="Primary colour"
				extra="Used on the sign-in, two-step and consent pages, only for people of this organization’s own projects. Shifted to a darker or lighter shade where the colour itself would be hard to read."
			>
				<PrimaryColorField />
			</Form.Item>
			<Form.Item
				name="policyUri"
				label="Privacy policy URL"
				extra="Linked on the consent page only when it is on the same host as a redirect URI."
			>
				<Input placeholder="https://app.example.com/privacy" />
			</Form.Item>
			<Form.Item
				name="tosUri"
				label="Terms of service URL"
				extra="Linked on the consent page only when it is on the same host as a redirect URI."
			>
				<Input placeholder="https://app.example.com/terms" />
			</Form.Item>
			{/*
			 * Free-form tags rather than a picker over the configured types: the server validates
			 * each value against them and reports its own message, and gating this field on the
			 * feature flag here would restate a server rule in a second place.
			 */}
			<Form.Item
				name="authorizationDetailsTypes"
				label="Authorization details types (RAR)"
			>
				<Select
					mode="tags"
					placeholder="https://scheme.example/payment"
				/>
			</Form.Item>
			<Form.Item<FormValues>
				shouldUpdate={(prev, cur) => prev.grantTypes !== cur.grantTypes}
			>
				{() => {
					const grantTypes =
						(form.getFieldValue('grantTypes') as string[] | undefined) ?? [];
					if (!grantTypes.includes(CIBA_GRANT_TYPE)) return null;
					return (
						<>
							<Form.Item
								name="backchannelTokenDeliveryMode"
								label="Backchannel token delivery mode"
								rules={[{ required: true }]}
							>
								<Select options={CIBA_DELIVERY_MODE_OPTIONS} />
							</Form.Item>
							<Form.Item
								name="backchannelClientNotificationEndpoint"
								label="Backchannel client notification endpoint"
							>
								<Input placeholder="https://app.example.com/ciba/notify" />
							</Form.Item>
						</>
					);
				}}
			</Form.Item>
			<Collapse
				ghost
				items={[
					{
						key: 'keys',
						label: 'Key & request security',
						forceRender: true,
						children: (
							<>
								<Form.Item
									name="jwksText"
									label="Key set (jwks)"
									tooltip="The client's public keys, for private_key_jwt and signed Request Objects. Public material only — a private key is refused. Use this or the key set URL, not both."
									rules={[
										{
											validator: async (_rule, text: string | undefined) => {
												parseJwks(text);
											}
										}
									]}
								>
									<Input.TextArea
										rows={4}
										spellCheck={false}
										placeholder='{"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…"}]}'
									/>
								</Form.Item>
								{KEY_TEXT_FIELDS.map(([name, label, placeholder]) => (
									<Form.Item
										key={name}
										name={name}
										label={label}
									>
										<Input placeholder={placeholder} />
									</Form.Item>
								))}
								<Form.Item
									name="subjectType"
									label="Subject type"
								>
									<Select
										allowClear
										options={[
											{ label: 'public', value: 'public' },
											{ label: 'pairwise', value: 'pairwise' }
										]}
									/>
								</Form.Item>
								{KEY_SWITCHES.map(([name, label]) => (
									<Form.Item
										key={name}
										name={name}
										label={label}
										valuePropName="checked"
									>
										<Switch />
									</Form.Item>
								))}
							</>
						)
					}
				]}
			/>
		</>
	);
}
