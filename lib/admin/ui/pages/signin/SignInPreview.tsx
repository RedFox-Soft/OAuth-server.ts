import { Alert, Card, Flex, Typography } from 'antd';
import type { FederationProvider } from '../../../../federation/types.js';
import { LoginPage } from '../../../../interactions/loginPage.js';
import { DEFAULT_LOGO } from '../../../../interactions/logo.js';
import { previewOptions, type PreviewDraft } from './previewOptions.js';
import { FederationOffNotice } from '../providers/FederationOffNotice.js';
import { brandConflicts } from '../../../../federation/brand_conflicts.js';
import { foxVarsFor } from '../../../../html/theme/palette.js';

/*
 * The bucket's sign-in page as people would meet it with the tab's switches as they stand, saved or not
 * (specs/091). The page itself, drawn by its own component from options decided by the server's own rule —
 * so it can only be wrong where the page is.
 *
 * `inert` takes every control inside out of reach at once: no focus, no click, no submit, and nothing read
 * out by a screen reader as if it were part of the console. Disabling controls one by one would miss the
 * next one somebody adds to the page.
 */
export function SignInPreview({
	bucketId,
	service,
	draft,
	providers,
	federationOn,
	loading
}: {
	bucketId: string;
	/* The name the page opens with: the project's display name, else its address. */
	service: string;
	draft: PreviewDraft;
	/* Null until read, or when the read failed: the buttons are then unknown, not absent. */
	providers: FederationProvider[] | null;
	/* Null when the summary could not be read, for the same reason. */
	federationOn: boolean | null;
	/* Still reading either: the page is drawn without buttons, and nothing is said to be missing yet. */
	loading: boolean;
}) {
	const known = providers !== null && federationOn !== null;
	const options = previewOptions({
		bucketId,
		draft,
		providers: known ? providers : [],
		federationOn: federationOn ?? false
	});

	/*
	 * Worked out here from the list already read, by the rule the server warns with (specs/105), so the preview can
	 * say why a button it draws is a problem without a request per provider.
	 */
	const conflicts = brandConflicts(known ? providers : []);
	const confusing = (known ? providers : [])
		.filter((provider) => conflicts.has(provider.id))
		.map((provider) => provider.displayName);

	return (
		<Card
			title="What people see"
			styles={{ body: { padding: 0 } }}
		>
			<Flex vertical>
				{known && !federationOn && providers.some((p) => p.enabled) && (
					<FederationOffNotice />
				)}
				{confusing.length > 0 && (
					<Alert
						type="warning"
						showIcon
						banner
						title={`Some buttons may confuse people: ${confusing.join(', ')}. Open each provider to see why.`}
					/>
				)}
				{!known && !loading && (
					<Alert
						type="warning"
						showIcon
						banner
						title="Identity providers could not be read; their buttons are not shown."
					/>
				)}
				{/*
				 * The light palette, declared here because the console's own page does not declare it: without it
				 * every colour the page reads from the palette resolved to nothing.
				 */}
				<div
					inert
					style={foxVarsFor('light')}
				>
					{/*
					 * The fold is drawn open: the preview is inert, so a closed one would hide from the administrator
					 * exactly which providers people have to open it to find.
					 */}
					<LoginPage
						embedded
						uid="preview"
						logoSrc={DEFAULT_LOGO}
						passwordLogin={options.passwordLogin}
						registrationOpen={options.registrationOpen}
						passwordReset={options.passwordReset}
						providers={options.providers}
						providersOpen
						face={{ service }}
					/>
				</div>
				<Typography.Text
					type="secondary"
					style={{ padding: '12px 16px' }}
				>
					Changes here as you change the switches, before you save. An
					authenticator requirement and email verification act after this
					screen, so they are not shown.
				</Typography.Text>
			</Flex>
		</Card>
	);
}
