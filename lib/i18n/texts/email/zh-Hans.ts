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
	}
};
