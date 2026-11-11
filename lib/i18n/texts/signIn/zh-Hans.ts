import type { SignInTexts } from './index.js';

export const zhHans: SignInTexts = {
	titles: {
		login: '登录',
		registration: '注册',
		totpEnroll: '设置身份验证器',
		totpVerify: '两步验证',
		codeRequired: '需要验证码'
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
		signInWith: '使用{provider}登录',
		listRefusal: {
			title: '此网络暂时无法使用密码登录',
			happened:
				'此网络的地址最近被用于猜测密码，因此本服务目前不接受来自该地址的密码。',
			whatNow:
				'您可以换一个网络再试，例如用移动数据代替 Wi-Fi，或使用本页上的其他登录方式。',
			support: '如果此情况持续发生，请将下面这一行发送给本服务的管理人员：',
			dispute: '请 FoxTrust 复核此地址'
		}
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
		verify: '验证',
		mailedHeading: '请查看您的邮箱',
		mailedHint:
			'身份验证器应用已从您的账号中移除。我们已向您发送了一个链接：请在 10 分钟内用此浏览器打开它，以设置新的身份验证器应用。',
		mailedResend: '发送新链接',
		linkHint:
			'我们已向您发送了一个链接。请在 10 分钟内用此浏览器打开它，以设置身份验证器应用。',
		continueApp: '继续进入 {app}',
		continueAny: '继续',
		everySignIn: '此后，每次使用密码登录 {service} 时都会要求输入验证码。'
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
			'此电子邮件地址在此处已有账户。请使用该账户的密码登录一次，以将其关联到您的身份提供商。',
		mailLimited: '您的网络在过去一小时内请求的邮件过多。请稍后再试。',
		freshSignIn: '{host} 要求您重新登录以打开此页面。',
		freshSignInCode:
			'{host} 要求您使用身份验证器应用中的验证码重新登录以打开此页面。',
		codeAskedByApp: '{app} 需要身份验证器应用中的验证码。',
		codeAsked: '您要登录的应用需要身份验证器应用中的验证码。'
	},

	codeRequired: {
		headingApp: '{app} 需要身份验证器应用中的验证码',
		headingAny: '您要登录的应用需要身份验证器应用中的验证码',
		noFactor:
			'您的账号 {email} 尚未设置身份验证器应用，因此无法以这种方式进入。',
		setUpHint:
			'设置大约需要两分钟：我们会通过电子邮件向您发送一个链接，然后您用手机上的应用（例如 Google Authenticator、Microsoft Authenticator 或 1Password）扫描二维码。',
		setUp: '设置身份验证器应用',
		askOperators: '{service} 不允许用户自行设置。请联系 {service} 的管理员。',
		provider:
			'您是通过 {provider} 登录的。通过 {provider} 登录时，此处无法使用身份验证器应用中的验证码，因此无法以这种方式进入。',
		passwordInstead: '改用密码登录',
		providerAsk: '请联系 {service} 的管理员。',
		returnApp: '不登录，返回 {app}',
		returnAny: '不登录，返回应用'
	},

	errors: {
		invalidCredentials: '用户名或密码无效',
		invalidCode: '验证码无效',
		passwordsDiffer: '两次输入的密码不一致',
		mailLimited: '您的网络在过去一小时内请求的邮件过多。请稍后再试。',
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
