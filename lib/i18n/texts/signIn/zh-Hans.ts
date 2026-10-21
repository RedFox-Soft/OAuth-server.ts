import type { SignInTexts } from './index.js';

export const zhHans: SignInTexts = {
	titles: {
		login: '登录',
		registration: '注册',
		totpEnroll: '设置身份验证器',
		totpVerify: '两步验证'
	},

	headings: {
		login: '登录您的{service}账户',
		loginToApp: '登录{app}',
		registration: '创建您的{service}账户',
		registrationForApp: '注册{app}'
	},

	login: {
		emailRequired: '请输入电子邮件地址！',
		emailPlaceholder: '电子邮件地址',
		passwordRequired: '请输入密码！',
		passwordPlaceholder: '密码',
		remember: '记住我',
		forgotPassword: '忘记密码',
		submit: '登录',
		registerPrompt: '或{link}',
		register: '立即注册！',
		resendLink: '重新发送链接',
		providersDivider: '或',
		moreProviders: '更多登录方式',
		signInWith: '使用{provider}登录'
	},

	registration: {
		emailRequired: '请输入电子邮件地址！',
		emailInvalid: '请输入有效的电子邮件地址！',
		emailPlaceholder: '电子邮件地址',
		passwordRequired: '请输入密码！',
		passwordPlaceholder: '密码',
		confirmRequired: '请确认密码！',
		confirmMismatch: '两次输入的密码不一致！',
		confirmPlaceholder: '确认密码',
		submit: '注册',
		loginPrompt: '或{link}',
		login: '登录已有账户'
	},

	totp: {
		enrollHeading: '设置您的身份验证器',
		verifyHeading: '两步验证',
		enrollHint: '请用身份验证器应用扫描此二维码，然后输入应用中显示的验证码。',
		verifyHint: '请输入身份验证器应用中当前显示的验证码。',
		manualKey: '或者手动输入此密钥：',
		codeRequired: '请输入验证码！',
		confirm: '确认',
		verify: '验证'
	},

	notices: {
		verify:
			'请查看收件箱——我们已通过电子邮件向您发送了验证地址的链接。打开该链接后，您就可以登录了。',
		federationAborted:
			'通过身份提供商登录未完成。您可以重试，或者使用密码登录。',
		verifyResent: '我们已向您发送了新的验证链接。请打开该链接，然后登录。',
		verifyRecent: '最近已发送过验证邮件。请查看收件箱，或者一分钟后重试。',
		verifyUnsent: '我们无法发送验证邮件。请稍后重试。',
		federationLink:
			'此电子邮件地址在此处已有账户。请使用该账户的密码登录一次，以将其关联到您的身份提供商。'
	},

	errors: {
		invalidCredentials: '用户名或密码无效',
		invalidCode: '验证码无效',
		passwordsDiffer: '两次输入的密码不一致',
		passwordTooShort: {
			other: '请至少使用{count}个字符。'
		},
		verificationSent: '我们已向{email}发送了验证链接。请打开该链接，然后登录。',
		verificationOutstanding:
			'登录前，请先验证您的电子邮件地址。请打开我们发送到{email}的链接。',
		verificationRecent: '最近已发送过验证邮件。请查看收件箱。',
		verificationUnsent: '我们无法发送验证邮件。请稍后重试。'
	}
};
