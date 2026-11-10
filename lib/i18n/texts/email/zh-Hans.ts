import type { EmailTexts } from './index.js';

export const zhHans: EmailTexts = {
	pasteLink: '或者将此链接粘贴到浏览器中：',
	verification: {
		heading: '验证您的电子邮件地址',
		intro: '感谢您注册{app}。请确认此电子邮件地址，以激活您的账户。',
		ignore: '如果您没有创建此账户，可以放心忽略这封电子邮件。',
		link: {
			subject: '验证您在{app}的电子邮件地址',
			button: '验证电子邮件地址',
			text: '验证您在{app}的电子邮件地址。\n\n打开此链接以确认您的地址：\n{url}\n\n如果您没有创建此账户，可以忽略这封电子邮件。'
		},
		code: {
			subject: '您的{app}验证码',
			prompt: '请输入此验证码，以确认您的地址：',
			expiry: '此验证码很快就会过期。请勿与任何人分享。',
			text: '验证您在{app}的电子邮件地址。\n\n您的验证码是：{code}\n\n此验证码很快就会过期。如果您没有创建此账户，可以忽略这封电子邮件。'
		}
	},
	passwordReset: {
		subject: '重置您的{app}密码',
		heading: '重置您的密码',
		intro: '我们收到了为您的{app}账户设置新密码的请求。',
		button: '设置新密码',
		expiry: '此链接将在一小时后过期，且只能使用一次。',
		ignore:
			'如果您没有请求重置密码，可以放心忽略这封电子邮件——您当前的密码仍然有效。',
		text: '重置您的{app}密码。\n\n打开此链接以设置新密码：\n{url}\n\n此链接将在一小时后过期，且只能使用一次。\n\n如果您没有请求重置密码，可以忽略这封电子邮件——您当前的密码仍然有效。'
	},
	invitation: {
		subject: '设置您在{bucket}的密码',
		heading: '您受邀加入{bucket}',
		intro: '管理员已在{bucket}为您创建了账户。请设置密码，即可开始登录。',
		button: '设置密码',
		expiry:
			'此链接在 7 天内有效，且只能使用一次。设置密码的同时也会确认此电子邮件地址。',
		ignore:
			'如果您并未预期收到这封邮件，可以忽略它——在设置密码之前，不会发生任何事情。',
		text: '您受邀加入{bucket}。\n\n管理员已为您创建了账户。打开此链接以设置您的密码：\n{url}\n\n此链接在 7 天内有效，且只能使用一次。设置密码的同时也会确认此电子邮件地址。\n\n如果您并未预期收到这封邮件，可以忽略它——在设置密码之前，不会发生任何事情。'
	},
	connectedAccount: {
		brokenSubject: '请重新连接您在{bucket}的{service}账户',
		brokenHeading: '您的{service}账户需要重新连接',
		brokenIntro:
			'您连接到{bucket}的{service}账户{label}已无法使用：{service}不再接受其访问权限。在您重新连接之前，您允许使用它的应用都无法使用它。',
		removedSubject: '您的{service}账户已与{bucket}断开连接',
		removedHeading: '您的{service}账户已断开连接',
		removedIntro:
			'{bucket}的一位管理员断开了您的{service}账户{label}。您允许使用它的应用将无法再使用它。',
		serviceRemovedIntro:
			'{bucket}不再提供{service}，因此您的{service}账户{label}已断开连接。您允许使用它的应用将无法再使用它。',
		button: '打开已连接的账户'
	},
	twoStep: {
		linkEnrolSubject: '为{service}开启两步验证',
		linkReplaceSubject: '将{service}的两步验证转移到另一部手机',
		linkReenrolSubject: '为{service}设置新的身份验证器应用',
		linkHeading: '确认是您本人',
		linkEnrolIntro:
			'有人（希望是您）开始为您在{service}的账户{email}开启两步验证。请在 10 分钟内用同一个浏览器打开此链接以继续。',
		linkReplaceIntro:
			'有人（希望是您）开始将您在{service}的账户{email}的两步验证转移到另一部手机。请在 10 分钟内用同一个浏览器打开此链接以继续。',
		linkReenrolIntro:
			'要以{email}完成登录{service}，请设置新的身份验证器应用。请在 10 分钟内用同一个浏览器打开此链接以继续。',
		linkWarning: '如果这不是您本人的操作，请修改密码。切勿转发此链接。',
		linkButton: '继续',
		onSubject: '您的{service}账户已开启两步验证',
		onIntro:
			'您在{service}的账户{email}已于{date}开启两步验证。今后每次用密码登录{service}时，还需要输入身份验证器应用中的验证码。',
		changedSubject: '两步验证已转移到另一部手机',
		changedIntro:
			'您在{service}的账户{email}的两步验证已于{date}转移到另一个身份验证器应用。旧应用中的验证码不再有效。',
		disownLine:
			'如果这不是您本人的操作，请在 72 小时内通过此链接将其移除，然后修改密码：',
		disownButton: '这不是我',
		offSubject: '您的{service}账户已关闭两步验证',
		offIntro:
			'您在{service}的账户{email}已于{date}关闭两步验证。现在登录只需要密码。',
		offWarning:
			'如果这不是您本人的操作，请修改密码，并告知{service}的运营人员。',
		removedSubject: '您的{service}账户的两步验证已被移除',
		removedIntro:
			'{service}的运营人员已于{date}从您的账户{email}中移除了身份验证器应用。现在登录只需要密码。',
		removedAgainSelf: '如需重新开启两步验证，请打开您的账户页面：',
		removedAgainRequired:
			'{service}要求所有人输入验证码，因此您将在下次登录时、在我们发送的邮件链接之后设置新的身份验证器应用。',
		removedWarning: '如果您没有提出此请求，请告知他们。',
		guessSubject: '有人用您的{service}密码登录',
		guessIntro:
			'有人用您账户{email}的密码登录了{service}，但随后未能提供身份验证器应用中的验证码。您的账户目前是安全的，但您的密码已不再是秘密。',
		guessAdvice: '请修改密码：在{service}的登录页面上选择“{forgot}”。',
		pageButton: '打开两步验证'
	}
};
