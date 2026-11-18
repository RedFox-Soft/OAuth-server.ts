export default {
	title: 'What FoxAuth records about people',
	description:
		'What a FoxAuth server keeps about the people who sign in to it, for how long, why, who reads it, and when it is deleted.',
	eyebrow: 'Privacy',
	heading: 'What FoxAuth records about people',
	lead: 'A FoxAuth server keeps a short record of what it decided about each person who signs in: when they signed in, when they were turned away and why, and which apps behind the operator’s proxy they used. This page lists all of it, so the operator of a project can point their own privacy notice here.',
	sections: [
		{
			heading: 'What is kept',
			items: [
				'Every sign-in: when, to which application, and how (a password, a password and a code, or a provider). The network address this server attributed the request to, the same one its rate limits use. The browser and system family, for example "Chrome on Windows". When network facts are turned on, the country and network kind (Tor, VPN, hosting) from FoxTrust’s snapshot, looked up on the server itself.',
				'Every failed sign-in where the account was found: a wrong password or code, a locked or deactivated account, a missing code, or an unverified address. An attempt on an address no account holds keeps nothing.',
				'Every time an app behind the operator’s proxy, or an API checked at it, asked the person to sign in again or refused them, with the reason. At an app, the person’s address is kept only when the proxy proves with the project’s proxy key that it passes the address. At an API, no address is kept: the caller there is the agent’s machine, not the person.',
				'What the person used there: one entry per app behind the proxy, or per API and application, and day, with the first and last time and how many checks the proxy made. For an API, the tools of its table the person called. Never an address, a country or a path.',
				'Beside each kept address, its network owner (the AS number and name), region and city, while the setting "Look up network owner and location at FoxTrust" is on. It is on by default. About a minute after the sign-in or refusal, the server sends the address to FoxTrust’s API, in a batch with others, and nothing else about the person. FoxTrust keeps none of these addresses.'
			]
		},
		{
			heading: 'What is never kept',
			items: [
				'The path or the query string of a request.',
				'The raw browser string.',
				'Tokens, passwords, codes or session identifiers.',
				'A tool name an MCP client sent that is not in the API’s table of tools.',
				'The address, country or path of a request the proxy let through.',
				'Anything FoxTrust’s API says about an address beyond its network owner, region and city.'
			]
		},
		{
			heading: 'How long',
			items: [
				'Each record is kept 90 days after it was last updated, then deleted. The 90 days are the same on every plan.',
				'A record survives a lock, a deactivation and "Sign out everywhere", because that is when an administrator needs it. It is deleted at once with the person, and with the project.',
				'Sign-ins and refusals are written once a minute, and what people used every five minutes. If a server process crashes, up to the last minute, or five for use, can be lost.',
				'Behind a proxy the server does not trust, every sign-in carries the proxy’s address. The operator fixes this with the "Caller address" settings.'
			]
		},
		{
			heading: 'Why',
			items: [
				'Knowing who signed in, from where, and why someone was refused protects the service and the people who use it. Processing this for that purpose is a legitimate interest in network and information security (GDPR, Recital 49).',
				'The operator of a project is the controller of this data. FoxAuth Cloud processes it on the operator’s behalf.',
				'For the lookups of network owner and location, RedFox Software (FoxTrust) is the operator’s processor, under FoxTrust’s terms at foxtrust.dev/terms.'
			]
		},
		{
			heading: 'Who reads it',
			items: [
				'The administrators of the project, on the person’s Activity tab, and the agents acting for them. Every read is written to the audit trail, once per reader, person and day.',
				'The same administrators, on an app’s or an API’s Access tab, see who it refused or asked to sign in again in the last 24 hours. That read is written to the audit trail too, once per reader, app or API, and day.',
				'The person themselves, on Recent sign-ins on their account page: their last ten sign-ins, with the app, the time, how they signed in, the browser and the country, but never the address. The page opens only after they sign in again within 15 minutes. From there they can sign out of every app at once, and a person with a password gets a link to set a new one.',
				'The server’s own administrators are recorded too, but only their sign-ins and refused sign-ins, with the same details and the same 90 days. Only a super administrator reads another administrator’s, under Administrators, and every read is written to the audit trail, once per reader, administrator and day. Each administrator sees their own last ten, without the address.',
				'A super administrator can turn recording off for the whole server in Settings.'
			]
		},
		{
			heading: 'Other records about people',
			items: [
				'To count monthly active users, a server marks each person once a day and once a month, without an address, when they sign in, when an app renews their tokens, and when the proxy lets them through. These marks outlive a deletion: a day’s mark for up to 40 days, a month’s mark for up to 13 months.',
				'Sessions and tokens carry no address and no device.',
				'When a project turns it on, and for the server’s own administrators unless a super administrator turns it off, the server emails a person about a sign-in from a network or a browser their account has not used in 90 days: when, where, how and with which browser, never the address, with a link that signs the account out everywhere. Only to a proven address, at most five a day. The sign-in’s record notes that the email was sent.'
			]
		}
	]
};
