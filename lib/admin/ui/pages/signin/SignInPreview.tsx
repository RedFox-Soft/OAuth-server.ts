import { Alert, Card, Flex, Typography } from 'antd';
import type { FederationProvider } from '../../../../federation/types.js';
import { LoginPage } from '../../../../interactions/loginPage.js';
import { DEFAULT_LOGO } from '../../../../interactions/logo.js';
import { previewOptions, type PreviewDraft } from './previewOptions.js';

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
	draft,
	providers,
	federationOn,
	loading
}: {
	bucketId: string;
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

	return (
		<Card
			title="What people see"
			styles={{ body: { padding: 0 } }}
		>
			<Flex vertical>
				{!known && !loading && (
					<Alert
						type="warning"
						showIcon
						banner
						title="Identity providers could not be read; their buttons are not shown."
					/>
				)}
				{/* The page's card is a fixed 400 px: on a narrow window it scrolls here, never the console. */}
				<div style={{ overflowX: 'auto' }}>
					<div inert>
						<LoginPage
							embedded
							uid="preview"
							logoSrc={DEFAULT_LOGO}
							passwordLogin={options.passwordLogin}
							registrationOpen={options.registrationOpen}
							passwordReset={options.passwordReset}
							providers={options.providers}
						/>
					</div>
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
