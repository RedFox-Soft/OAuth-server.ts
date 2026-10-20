import type { PlainTexts } from './index.js';

export const zhHans: PlainTexts = {
	verify: {
		success: {
			title: '电子邮件地址已验证',
			heading: '电子邮件地址已验证',
			body: '您的电子邮件地址已确认。请返回登录页面登录。',
			console: '前往控制台'
		},
		failure: {
			title: '验证失败',
			heading: '验证失败',
			hint: '请返回应用并重新登录，以接收新的验证邮件。'
		},
		code: {
			title: '输入验证码',
			heading: '输入您的验证码',
			lead: '我们已通过电子邮件向您发送了一个 6 位数的验证码。',
			submit: '验证',
			resend: '发送新的验证码'
		},
		resendAccepted: {
			title: '验证邮件已发送',
			heading: '请查看您的邮箱',
			body: '如果您的账户仍需验证，我们已向您发送了一封新的验证邮件。'
		},
		rateLimited: {
			title: '请稍候',
			heading: '请求过于频繁'
		},
		messages: {
			invalidLink: '此验证链接无效或已过期。请在下方重新请求验证邮件。',
			invalidRequest: '此验证请求无效或已过期。请在下方重新请求验证码。',
			tooManyAttempts: '输错次数过多。请在下方重新请求验证码。',
			incorrectCode: '验证码不正确，请重试。',
			cooldown: '请稍等片刻，再请求新的验证邮件。',
			dailyCap: '您今天请求的验证邮件过多。请稍后再试。'
		}
	},
	reset: {
		request: {
			title: '重置您的密码',
			heading: '重置您的密码',
			lead: '请输入您账户的电子邮件地址，我们会向您发送一个用于设置新密码的链接。',
			emailPlaceholder: 'you@example.com',
			submit: '发送重置链接',
			back: '返回登录'
		},
		accepted: {
			title: '请查看您的邮箱',
			heading: '请查看您的邮箱',
			body: '如果该地址对应一个账户，密码重置链接正在发送途中。该链接将在一小时后过期。',
			hint: '没有收到？请先检查垃圾邮件文件夹。新链接每分钟最多发送一次，每天也只能发送几次；在此之前再次请求，不会发送任何邮件。'
		},
		form: {
			title: '设置新密码',
			password: '新密码',
			confirm: '再次输入新密码',
			submit: '设置新密码',
			mismatch: '两次输入的密码不一致。'
		},
		inviteForm: {
			title: '设置您在{bucket}的密码',
			lead: '请设置您登录时使用的密码。设置密码的同时也会确认您的电子邮件地址。',
			password: '密码',
			confirm: '再次输入密码',
			submit: '设置密码'
		},
		success: {
			title: '密码已更新',
			heading: '密码已更新',
			body: '您的密码已更改，并且您已在所有地方退出登录。请返回应用重新登录。'
		},
		inviteSuccess: {
			title: '密码已设置',
			heading: '您的密码已设置',
			body: '现在您可以登录了。请返回应用，使用您的电子邮件地址和刚刚设置的密码登录。'
		},
		failure: {
			title: '链接无效',
			heading: '此链接已失效',
			body: '重置链接在一小时后过期，邀请链接在 7 天后过期；新链接会取代旧链接，且每个链接只能使用一次。',
			hint: '请在应用的登录页面重新请求重置链接，或者请邀请您的人再发送一次邀请。'
		}
	},
	registration: {
		closed: {
			title: '注册已关闭',
			heading: '暂不接受新账户',
			body: '此应用目前不接受新账户注册。',
			hint: '如果您已有账户，请返回应用并登录。'
		},
		sendFailed: {
			title: '验证邮件未发送',
			heading: '我们无法发送您的验证邮件',
			body: '您的账户已创建，但验证邮件未能发送。请返回应用并登录，系统会再为您发送一封。'
		}
	},
	untrustedRedirect: {
		declined: '您已拒绝该请求',
		failed: '无法完成该请求',
		returnTo: '返回{host}',
		waiting: '{host}上的应用正在等待此响应。仅当您信任该网站时，才继续。',
		error: '错误：{error}'
	},
	federation: {
		backToSignIn: '返回登录',
		rejected: {
			title: '无法完成登录',
			body: '我们无法验证来自您的身份提供商的响应。请重新开始。'
		},
		expired: {
			title: '此次登录已失效',
			body: '登录耗时过长，或者此链接已被使用过。请从应用重新开始。'
		},
		upstream: {
			title: '无法连接到您的身份提供商',
			body: '我们未能与您的身份提供商完成信息交换。这通常是暂时性问题，请稍后重试。'
		},
		noEmail: {
			title: '您的身份提供商没有提供电子邮件地址',
			body: '我们需要电子邮件地址才能让您登录，但您的身份提供商没有提供。请让您的管理员向此应用开放您的电子邮件地址。'
		},
		domainRefused: {
			title: '此账户无法使用此应用',
			body: '您的电子邮件地址不属于此应用接受的域名。'
		},
		linkRefused: {
			title: '此地址已有账户',
			body: '此电子邮件地址在此处已有账户。请改用密码登录。',
			link: '使用密码登录'
		},
		provisioningClosed: {
			title: '此处还没有您的账户',
			body: '此应用不会自动创建账户。请先让您的管理员为您创建一个账户。'
		},
		inactive: {
			title: '此账户已停用',
			body: '您的账户已被停用。请联系您的管理员。'
		},
		passwordLoginClosed: {
			title: '密码登录不可用',
			body: '此应用通过您的身份提供商为您登录。此处没有需要输入、重置或注册的密码。'
		}
	}
};
