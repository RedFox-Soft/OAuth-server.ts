/*
 * The sign-in pages: password sign-in, registration, two-step verification, and the messages the server puts
 * on them. A message is chosen by the server and rendered in the interaction's language; nothing a request
 * carries becomes text here (see lib/interactions/notices.ts).
 */

export const en = {
	titles: {
		login: 'Sign in',
		registration: 'Create account',
		totpEnroll: 'Set Up Authenticator',
		totpVerify: 'Two-Step Verification',
		codeRequired: 'Two-Step Sign-In Needed'
	},

	/*
	 * The heading under the project's name (signInMasthead.tsx). The application is named only when its project
	 * stands behind it; otherwise the page names the account the person is signing in to.
	 */
	headings: {
		login: 'Sign in to your {service} account',
		loginToApp: 'Sign in to {app}',
		registration: 'Create your {service} account',
		registrationForApp: 'Create an account for {app}'
	},

	login: {
		emailRequired: 'Please input your Email!',
		emailPlaceholder: 'Email',
		passwordRequired: 'Please input your Password!',
		passwordPlaceholder: 'Password',
		remember: 'Remember me',
		forgotPassword: 'Forgot password',
		submit: 'Log in',
		registerPrompt: 'or {link}',
		register: 'Register now!',
		resendLink: 'Send the link again',
		/* The line between the password form and the provider buttons. */
		providersDivider: 'or',
		/* Opens the providers folded away on a page with many of them (specs/105). */
		moreProviders: 'More sign-in options',
		// The provider's own name from the built-in catalogue, never the name an administrator gave it.
		signInWith: 'Sign in with {provider}',
		/*
		 * Signing in with a passkey (specs/139): the button, in every form of the page; the line shown when scripts are
		 * off; the line after the person closed the browser's prompt without choosing one.
		 */
		passkey: 'Sign in with a passkey',
		passkeyNoScript: 'Signing in with a passkey needs JavaScript.',
		passkeyCancelled: 'No passkey on this device? Sign in another way below.',
		/*
		 * In place of the password form when this network's address is on FoxTrust's list and has just failed
		 * passwords here (specs/125). Says what to do now; the support line and the dispute link follow as their
		 * own elements, never as values inside these sentences.
		 */
		listRefusal: {
			title: 'Password sign-in is not available from this network',
			happened:
				"This network's address was recently used to guess passwords, so this service is not accepting passwords from it right now.",
			whatNow:
				'You can try again from another network, for example mobile data instead of Wi-Fi, or use one of the other ways to sign in on this page.',
			support:
				'If this keeps happening, send this line to the people who run this service:',
			dispute: 'Ask FoxTrust to review this address'
		}
	},

	registration: {
		emailRequired: 'Please input your Email!',
		emailInvalid: 'Please enter a valid Email!',
		emailPlaceholder: 'Email',
		passwordRequired: 'Please input your Password!',
		passwordPlaceholder: 'Password',
		confirmRequired: 'Please confirm your Password!',
		confirmMismatch: 'Passwords do not match!',
		confirmPlaceholder: 'Confirm Password',
		submit: 'Register',
		loginPrompt: 'or {link}',
		login: 'Already have an account?'
	},

	totp: {
		enrollHeading: 'Set up your authenticator',
		verifyHeading: 'Two-step verification',
		enrollHint:
			'Scan this with an authenticator app, then enter the code it shows.',
		verifyHint: 'Enter the current code from your authenticator app.',
		manualKey: 'Or enter this key manually:',
		codeRequired: 'Please enter your code!',
		confirm: 'Confirm',
		verify: 'Verify',
		/* After an administrator removed the person's authenticator (specs/126): the new one is proved by mail first. */
		mailedHeading: 'Check your email',
		mailedHint:
			'Your authenticator app was removed from your account. We sent you a link: open it in this browser within 10 minutes to set up a new one.',
		mailedResend: 'Send a new link',
		/* Setting one up from an application that requires it (specs/127), after the link in the mail. */
		linkHint:
			'We sent you a link. Open it in this browser within 10 minutes to set up an authenticator app.',
		continueApp: 'Continue to {app}',
		continueAny: 'Continue',
		everySignIn:
			'From now on, a code will be asked at every password sign-in to {service}.'
	},

	notices: {
		verify:
			'Check your inbox — we have emailed you a link to verify your address. You will be able to sign in once you have opened it.',
		federationAborted:
			'Sign-in with your identity provider was not completed. You can try again, or sign in with your password.',
		verifyResent:
			'We sent you a new verification link. Follow it, then sign in.',
		verifyRecent:
			'A verification message was sent recently. Check your inbox, or try again in a minute.',
		verifyUnsent:
			'We could not send the verification message. Try again later.',
		federationLink:
			'An account with this email address already exists here. Sign in with its password once to link it to your identity provider.',
		mailLimited:
			'Too many emails were requested from your network in the last hour. Please try again later.',
		/* An app behind a proxy that asks for a recent sign-in (specs/124 FR-022). */
		freshSignIn: '{host} asks you to sign in again to open this page.',
		/* The same, when the page also asks for a code from an authenticator app (specs/128). */
		freshSignInCode:
			'{host} asks you to sign in again with a code from an authenticator app to open this page.',
		/* An application that requires a code, before this sign-in has one (specs/127). */
		codeAskedByApp: '{app} asks for a code from an authenticator app.',
		codeAsked:
			'The app you’re signing in to asks for a code from an authenticator app.',
		/* From the two-step sign-in page's "Sign in with a passkey" (specs/139). */
		passkey: 'Sign in with your passkey to continue.',
		/* The page was older than its passkey challenge, or another tab replaced it: nothing was judged. */
		passkeyRetry: 'Try again.'
	},

	/*
	 * An API the app connects to requires a sign-in with a code, or a recent one (specs/130). The API is named: the
	 * project declared it. The app never is, unless the project stands behind it.
	 */
	apiNotices: {
		codeAsked: '{api} asks for a code from an authenticator app to connect.',
		everyHour: '{api} asks you to sign in again every hour to stay connected.',
		everyDay: '{api} asks you to sign in again every day to stay connected.',
		everyHours: {
			one: '{api} asks you to sign in again every {count} hour to stay connected.',
			other:
				'{api} asks you to sign in again every {count} hours to stay connected.'
		},
		everyDays: {
			one: '{api} asks you to sign in again every {count} day to stay connected.',
			other:
				'{api} asks you to sign in again every {count} days to stay connected.'
		}
	},

	/*
	 * An application that requires a code from an authenticator app, reached by a sign-in that gave none (specs/127).
	 * The app is named only where the page may name it (the masthead rule); a value is always a value.
	 */
	codeRequired: {
		headingApp: '{app} asks for two-step sign-in',
		headingAny: 'The app you’re signing in to asks for two-step sign-in',
		noFactor:
			'Your account, {email}, doesn’t have an authenticator app set up yet, so you can’t open it this way.',
		setUpHint:
			'Setting one up takes about two minutes: we email you a link, then you scan a QR code with an app on your phone, for example Google Authenticator, Microsoft Authenticator or 1Password.',
		setUp: 'Set up an authenticator app',
		askOperators:
			'{service} doesn’t let people set one up themselves. Ask the people who run {service}.',
		provider:
			'You signed in with {provider}. A code from an authenticator app can’t be used with a sign-in through {provider} here, so you can’t open it this way.',
		passwordInstead: 'Sign in with a password instead',
		providerAsk: 'Ask the people who run {service}.',
		returnApp: 'Return to {app} without signing in',
		returnAny: 'Return to the app without signing in',
		/* In a project that accepts passkeys (specs/139): a passkey sign-in meets the requirement. */
		passkey: 'Sign in with a passkey',
		passkeyHeldApp:
			'You have a passkey for {email}. Sign in with it to open {app}.',
		passkeyHeldAny:
			'You have a passkey for {email}. Sign in with it to continue.'
	},

	errors: {
		invalidCredentials: 'Invalid username or password',
		invalidCode: 'Invalid code',
		/* A code accepted moments ago, typed again: another sign-in window used it (specs/130 research R10). */
		codeJustUsed: 'This code was just used. Wait for the next one.',
		passwordsDiffer: 'Passwords do not match',
		mailLimited:
			'Too many emails were requested from your network in the last hour. Please try again later.',
		passwordTooShort: {
			one: 'Use at least {count} character.',
			other: 'Use at least {count} characters.'
		},
		verificationSent:
			'We sent a verification link to {email}. Follow it, then sign in.',
		verificationOutstanding:
			'Please verify your email before signing in. Follow the link we sent to {email}.',
		verificationRecent:
			'A verification message was sent recently. Check your inbox.',
		verificationUnsent:
			'We could not send the verification message. Try again later.',
		/*
		 * The passkey door (specs/139). One sentence for every passkey it cannot use, whoever's it is, so it says nothing
		 * about whether the passkey is known anywhere (FR-008); the account's refusal never mentions a password (FR-014).
		 */
		passkeyRefused:
			'This passkey isn’t for {service}. Choose another one, or sign in another way.',
		passkeyAccount:
			'This account can’t sign in right now. Ask the people who run {service}.',
		passkeyLimited:
			'Too many passkey attempts from your network. Try again later, or sign in another way.'
	}
} as const;
