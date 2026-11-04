import { rich } from '../../types.ts';

/*
 * The words of the "What do you need?" page around the answers: headings, labels, buttons and the diagram key. The
 * answers themselves (titles, sentences, captions, diagram labels and steps) come from the guide data, through
 * guide-texts.ts.
 */
export default {
	title: 'What do you need?',
	description:
		'Answer two questions and see which sign-in setup fits: what happens step by step, what the person sees, and one button that sets it up.',
	lead: 'Two questions, one picture, and one button that sets it up.',
	tabs: {
		legend: 'Which part of the guide',
		product: 'Your product',
		productSub: 'sign-in for people and agents',
		enterprise: 'Enterprise',
		enterpriseSub: 'your customer is a company'
	},
	questions: {
		first: 'Who is acting?',
		moreTasks: 'More common tasks',
		moreTasksSub: 'Not a sign-in flow, but often the next thing you need.',
		pickSecond: 'Choose an answer to question 2 to see it here.',
		backToQuestions: rich('This shows the task you picked. ', {
			link: 'Show the answer to the two questions again',
			href: '#g-panel-product'
		}),
		agentNative: rich(
			'Does the agent run on the person’s computer and sign in as them? That is the same case as ',
			{ link: 'an app on a desktop or in a terminal', href: '#answer-native' },
			'.'
		)
	},
	enterprise: {
		tag: 'Your customer’s company',
		heading:
			'When your customer is a company: what their IT department will ask for',
		lead: 'An ordinary app needs none of this. Pick what the company is asking for.',
		together:
			'Company sign-in and SCIM come first. They usually arrive together.',
		togetherTag: 'Usually together',
		legend: 'What is the company asking for?',
		picture: {
			employees: 'Employees',
			directory: 'Company directory',
			idp: 'Okta or Entra ID',
			yourApp: 'Your app with FoxAuth'
		}
	},
	status: {
		ready: 'Ready on Cloud',
		ownServer: 'Own server',
		notOnFree: 'Paid plan'
	},
	strip: {
		label: 'The problem, the fix, and what you get',
		problem: 'Your problem',
		fix: 'With FoxAuth',
		get: 'What you get'
	},
	answer: {
		persona: {
			person: 'A person',
			program: 'A program',
			agent: 'An AI agent',
			enterprise: 'Enterprise'
		},
		marks: {
			ready: 'Ready on FoxAuth Cloud',
			ownServer: 'On your own server',
			notOnFree: 'Not on the Free plan'
		},
		setUp: 'Set this up',
		destination: 'Opens in FoxAuth Cloud, in your project.',
		destinationSub: 'You sign in first, or create a free account.',
		ownServerFlag:
			'FoxAuth Cloud has this switched off. Your own server has it.',
		ownServerSuper:
			'This needs a super administrator, and on FoxAuth Cloud nobody is one. On your own server, a super administrator sets it up.',
		ownServerRoute: 'Run your own server',
		notOnFree:
			'The Free plan on FoxAuth Cloud does not include this. Paid plans are in development, and your own server has it today.',
		seePlans: 'See the plans',
		requestPlan: 'Ask for a paid plan',
		next: 'Next:',
		selfHostedFlags: 'On your own server, switch on in Settings:',
		selfHostedAnyOf: 'On your own server, switch on one of these in Settings:',
		selfHostedNone: 'On your own server, this needs no setting switched on.',
		switchFlags: 'Switch on in Settings:',
		switchAnyOf: 'Switch on one of these in Settings:',
		alsoAnyOf: 'And one of these:',
		and: 'and',
		or: 'or',
		steps: 'How it works, step by step',
		prevStep: 'Previous step',
		nextStep: 'Next step',
		replay: 'Show again',
		goodToKnow: 'Good to know',
		underTheHood: 'Under the hood:',
		prompt: 'Prompt for your agent',
		promptNote:
			'Paste it into Claude, Cursor or another coding agent. It covers your code and the console setup. The prompt is in English.',
		copy: 'Copy prompt',
		copied: 'Copied',
		copyFailed:
			'The browser did not allow copying. Select the text and copy it.'
	},
	mini: {
		signIn: {
			heading: 'Sign in',
			email: 'Email',
			password: 'Password',
			submit: 'Sign in',
			or: 'or',
			provider: 'Continue with Google'
		},
		signUp: {
			heading: 'Create an account',
			submit: 'Create account',
			haveAccount: 'Already have an account? Sign in'
		},
		companySignIn: {
			before: 'Continue with ',
			after: ''
		},
		consent: {
			heading: 'An app asks for access',
			body: 'It will act on your behalf.',
			deny: 'Deny',
			allow: 'Allow'
		},
		agentConsent: {
			asks: 'asks to act on your behalf',
			scopes: ['Read your notes', 'Add new notes']
		},
		adminConsent: {
			brand: 'FoxAuth administration',
			asks: 'asks to act as you',
			scopes: [
				'See your projects and applications',
				'Create and change applications'
			]
		},
		serviceConsent: {
			connect: 'Connect your account',
			body: 'Your agent can then use it on your behalf, through FoxAuth.',
			cancel: 'Cancel',
			allow: 'Connect'
		},
		deviceCode: {
			heading: 'Type the code from the screen',
			code: 'WDJB-MJHT',
			submit: 'Next'
		},
		approve: {
			heading: 'Approve a request?',
			body: 'Who is asking, and for what.',
			decline: 'Decline',
			approve: 'Approve'
		}
	},
	legend: {
		fox: 'FoxAuth',
		outside: 'Outside your control',
		request: 'A message',
		redirect: 'The browser is sent on',
		token: 'Carries a token',
		refusal: 'A refusal',
		self: 'Happens inside one box'
	},
	all: {
		heading: 'All situations',
		summary: 'Show all situations',
		caption:
			'Every situation in the guide, the protocol behind it, and whether FoxAuth Cloud can set it up.',
		situation: 'Situation',
		protocol: 'Under the hood',
		mark: 'On FoxAuth Cloud',
		product: 'Your product',
		enterprise: 'Enterprise'
	},
	nothingFits: {
		heading: 'Nothing fits? Configure everything yourself',
		body: 'Every application can be set up by hand. The console’s full form names every field the way the protocol does, with nothing preset.',
		firstClient: 'Register your first application',
		settings: 'Read the settings reference'
	}
};
