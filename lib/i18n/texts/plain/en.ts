export const en = {
	verify: {
		success: {
			title: 'Email verified',
			heading: 'Email verified',
			body: 'Your email address has been confirmed. You can now sign in.'
		},
		failure: {
			title: 'Verification failed',
			heading: 'Verification failed',
			hint: 'Please return to the application and sign in again to receive a new verification message.'
		},
		code: {
			title: 'Enter verification code',
			heading: 'Enter your code',
			lead: 'We emailed you a 6-digit verification code.',
			submit: 'Verify',
			resend: 'Send a new code'
		},
		resendAccepted: {
			title: 'Verification email sent',
			heading: 'Check your email',
			body: 'If your account still needs verification, a new verification email has been sent.'
		},
		rateLimited: {
			title: 'Please wait',
			heading: 'Too many requests'
		},
		/* What the verification routes put on these pages. */
		messages: {
			invalidLink:
				'This verification link is invalid or has expired. Request a new verification email below.',
			invalidRequest:
				'This verification request is invalid or has expired. Request a new code below.',
			tooManyAttempts: 'Too many incorrect attempts. Request a new code below.',
			incorrectCode: 'Incorrect code. Please try again.',
			cooldown:
				'Please wait a moment before requesting another verification email.',
			dailyCap:
				'You have requested too many verification emails today. Please try again later.'
		}
	},
	reset: {
		request: {
			title: 'Reset your password',
			heading: 'Reset your password',
			lead: 'Enter the email address for your account and we will send you a link to choose a new password.',
			emailPlaceholder: 'you@example.com',
			submit: 'Send reset link',
			back: 'Back to sign in'
		},
		accepted: {
			title: 'Check your email',
			heading: 'Check your email',
			body: 'If that address has an account, a password reset link is on its way. The link expires in one hour.',
			hint: 'Not seeing it? Check your spam folder first. A new link is sent at most once a minute and a few times a day, so a request made sooner than that sends nothing.'
		},
		form: {
			title: 'Choose a new password',
			password: 'New password',
			confirm: 'Repeat new password',
			submit: 'Set new password',
			/* What the reset route puts on the form when the two fields differ. */
			mismatch: 'Those passwords do not match.'
		},
		inviteForm: {
			title: 'Set your password for {bucket}',
			lead: 'Choose the password you will sign in with. Setting it also confirms your email address.',
			password: 'Password',
			confirm: 'Repeat password',
			submit: 'Set password'
		},
		success: {
			title: 'Password updated',
			heading: 'Password updated',
			body: 'Your password has been changed and you have been signed out everywhere. Return to the application to sign in.'
		},
		inviteSuccess: {
			title: 'Password set',
			heading: 'Your password is set',
			body: 'You can sign in now. Return to the application and sign in with your email address and the password you just chose.'
		},
		failure: {
			title: 'Link invalid',
			heading: 'This link is no longer valid',
			body: 'Reset links expire after an hour and invitation links after 7 days; a newer one replaces an older one, and each works once.',
			hint: "Request a new reset link from the application's sign-in page, or ask whoever invited you to send another invitation."
		}
	},
	registration: {
		closed: {
			title: 'Registration closed',
			heading: 'Not accepting new accounts',
			body: 'This application is not accepting new accounts at the moment.',
			hint: 'If you already have an account, return to the application and sign in.'
		},
		sendFailed: {
			title: 'Verification email not sent',
			heading: 'We could not send your verification email',
			body: 'Your account was created, but the verification message could not be sent. Return to the application and sign in to have another one sent.'
		}
	},
	untrustedRedirect: {
		declined: 'You declined the request',
		failed: 'The request could not be completed',
		returnTo: 'Return to {host}',
		waiting:
			'The application at {host} is waiting for this answer. Continue only if you trust that site.',
		error: 'Error: {error}'
	},
	federation: {
		backToSignIn: 'Back to sign in',
		rejected: {
			title: 'Sign-in could not be completed',
			body: 'We could not verify the response from your identity provider. Please start again.'
		},
		expired: {
			title: 'This sign-in is no longer valid',
			body: 'The sign-in took too long, or this link has already been used. Please start again from the application.'
		},
		upstream: {
			title: 'Your identity provider could not be reached',
			body: 'We could not complete the exchange with your identity provider. This is usually temporary — please try again shortly.'
		},
		noEmail: {
			title: 'Your identity provider sent no email address',
			body: 'We need an email address to sign you in, and your identity provider did not supply one. Ask your administrator to release your address to this application.'
		},
		domainRefused: {
			title: 'This account cannot use this application',
			body: 'Your email address is not in a domain this application accepts.'
		},
		linkRefused: {
			title: 'An account already exists for this address',
			body: 'An account with this email address already exists here. Sign in with your password instead.',
			link: 'Sign in with your password'
		},
		provisioningClosed: {
			title: 'No account here yet',
			body: 'This application does not create accounts automatically. Ask your administrator to create one for you first.'
		},
		inactive: {
			title: 'This account is not active',
			body: 'Your account has been deactivated. Please contact your administrator.'
		},
		passwordLoginClosed: {
			title: 'Password sign-in is not available',
			body: 'This application signs you in through your identity provider. There is no password to enter, reset, or register here.'
		}
	}
} as const;
