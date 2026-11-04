import { rich } from '../../types.ts';

/*
 * The words of the "What do you need?" page around the answers: headings, labels, buttons and the legend. The answers
 * themselves (titles, sentences, diagram labels and steps) come from the guide data, through guide-texts.ts.
 */
export default {
	title: 'What do you need?',
	description:
		'Answer two questions and see which sign-in setup fits: what happens step by step, what the person sees, and one button that sets it up.',
	lead: 'Answer two questions about your product, or pick what your customer’s company asks for. The answer below shows what happens, step by step. One button sets it up in your project on FoxAuth Cloud.',
	tabs: {
		legend: 'Which part of the guide',
		product: 'Your product: sign-in for people and agents',
		productShort: 'Your product',
		enterprise: 'Your customer is a company (Enterprise)',
		enterpriseShort: 'Enterprise'
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
		ownServerFlag: 'FoxAuth Cloud has this switched off.',
		ownServerSuper:
			'This needs a super administrator, and on FoxAuth Cloud nobody is one. On your own server, a super administrator sets it up.',
		runOwnServer: rich('How to run your own server: ', {
			link: 'Run with Docker Compose',
			href: '/docs/get-started/docker-compose/'
		}),
		notOnFree:
			'The Free plan on FoxAuth Cloud does not include this. Paid plans are in development, and your own server has it today.',
		seePlans: 'See the plans',
		selfHostedFlags: 'On your own server, switch on in Settings:',
		selfHostedAnyOf: 'On your own server, switch on one of these in Settings:',
		selfHostedNone: 'On your own server, this needs no setting switched on.',
		switchFlags: 'Switch on in Settings:',
		switchAnyOf: 'Switch on one of these in Settings:',
		alsoAnyOf: 'And one of these:',
		and: 'and',
		or: 'or',
		steps: 'How it works, step by step',
		replay: 'Show the steps again',
		sees: 'What the person will see',
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
			heading: 'Sign in to Your app',
			email: 'Email',
			password: 'Password',
			submit: 'Sign in',
			provider: 'Continue with Google'
		},
		consent: {
			heading: 'Your app asks for access',
			body: 'It will act on your behalf.',
			deny: 'Deny',
			allow: 'Allow'
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
		heading: 'How to read the diagrams',
		summary: 'Show the legend',
		fox: 'FoxAuth is always the coloured box.',
		plain: 'A plain box is you, your code or the person.',
		outside:
			'A dashed box is a service outside your control, or your customer’s company.',
		redirect:
			'A dashed arrow sends the person’s browser on to another address.',
		token: 'A thick arrow carries a token.',
		refusal: 'A red dashed arrow is a refusal.',
		self: 'A step inside one box happens there, with no message sent.',
		numbers:
			'The steps are numbered, and the list under each diagram says the same in words.'
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
