/*
 * The sign-in pages: password sign-in, registration, two-step verification, and the messages the server puts
 * on them. A message is chosen by the server and rendered in the interaction's language; nothing a request
 * carries becomes text here (see lib/interactions/notices.ts).
 */

export const en = {
	titles: {
		login: 'Login Page',
		registration: 'Registration Page',
		totpEnroll: 'Set Up Authenticator',
		totpVerify: 'Two-Step Verification'
	},

	logoAlt: 'Logo',

	login: {
		usernameRequired: 'Please input your Username!',
		usernamePlaceholder: 'Username',
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
		signInWith: 'Sign in with {provider}'
	},

	registration: {
		heading: 'Create Account',
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
		verify: 'Verify'
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
			'An account with this email address already exists here. Sign in with its password once to link it to your identity provider.'
	},

	errors: {
		invalidCredentials: 'Invalid username or password',
		invalidCode: 'Invalid code',
		passwordsDiffer: 'Passwords do not match',
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
			'We could not send the verification message. Try again later.'
	}
} as const;
