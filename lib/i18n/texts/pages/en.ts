export const en = {
	error: {
		/* The page's own heading, by kind of error: the code and its description below stay as the protocol says. */
		headings: {
			notFound: 'This page does not exist',
			forbidden: 'This request is not allowed',
			serverError: 'Something went wrong on our side',
			failed: 'This request could not be completed'
		},
		details: 'Details for the application’s developer:',
		/*
		 * Follows the error's own description, which stays in English in every language. The reference is a
		 * random identifier a person quotes to an operator.
		 */
		reference: '(reference: {reference})'
	},
	device: {
		input: {
			title: 'Sign-in',
			heading: 'Sign-in',
			prompt: 'Enter the code displayed on your device',
			continue: 'Continue'
		},
		errors: {
			incorrectCode: 'The code you entered is incorrect. Try again',
			aborted: 'The Sign-in request was interrupted',
			unfinished:
				'The sign-in could not be completed. Your device has been told.',
			failed: 'There was an error processing your request'
		},
		confirm: {
			title: 'Device Login Confirmation',
			heading: 'Confirm Device',
			// Shown under the application's name and above the code the device should be displaying.
			codeIntro: 'The following code should be displayed on your device',
			warning:
				'If you did not initiate this action, the code does not match or are unaware of such device in your possession please close this window or click abort.',
			continue: 'Continue',
			abort: '[ Abort ]'
		},
		success: {
			title: 'Sign-in Success',
			heading: 'Sign-in Success',
			// For an application with no name to show.
			message: 'Your sign-in was successful, you can now close this page.',
			messageWithApp:
				'Your sign-in with {app} was successful, you can now close this page.'
		}
	},
	userCode: {
		placeholder: 'Enter code'
	},
	logout: {
		title: 'Logging Out',
		logoAlt: 'Logo',
		question: 'Do you want to sign-out?',
		stay: 'No, stay signed in',
		signOut: 'Yes, sign me out'
	},
	logoutSuccess: {
		title: 'Logging Out',
		logoAlt: 'Logo',
		message: 'You have been signed out successfully'
	},
	formPost: {
		title: 'Submitting Callback',
		// The page normally submits itself before anyone reads it; this is for a browser running no script.
		noscript: "Your browser does not support JavaScript or you've disabled it.",
		continue: 'Continue'
	}
} as const;
