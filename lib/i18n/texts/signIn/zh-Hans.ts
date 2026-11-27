import type { SignInTexts } from './index.js';

export const zhHans: SignInTexts = {
	titles: {
		login: '登录',
		registration: '注册',
		totpEnroll: '设置身份验证器',
		totpVerify: '两步验证',
		codeRequired: '需要两步登录',
		passkeyOffer: '下次登录更快',
		passkeyRequired: '需要使用通行密钥登录'
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
		passkey: '使用通行密钥登录',
		forgotPasskey: '丢失了通行密钥？',
		passkeyNoScript: '使用通行密钥登录需要启用 JavaScript。',
		passkeyCancelled: '此设备上没有通行密钥？请使用下方的其他方式登录。',
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
		federationLinkPasskey:
			'此电子邮件地址在此处已有使用通行密钥的账户。请使用您的通行密钥登录以将其关联到您的身份提供商。',
		mailLimited: '您的网络在过去一小时内请求的邮件过多。请稍后再试。',
		freshSignIn: '{host} 要求您重新登录以打开此页面。',
		freshSignInCode:
			'{host} 要求您使用身份验证器应用中的验证码重新登录以打开此页面。',
		freshSignInPasskey: '{host} 要求您使用通行密钥重新登录以打开此页面。',
		codeAskedByApp: '{app} 需要身份验证器应用中的验证码。',
		codeAsked: '您要登录的应用需要身份验证器应用中的验证码。',
		passkey: '请使用您的通行密钥登录以继续。',
		passkeyRetry: '请重试。'
	},

	apiNotices: {
		passkeyAsked: '{api} 要求您使用通行密钥登录才能连接。',
		codeAsked: '{api} 需要身份验证器应用中的验证码才能连接。',
		everyHour: '{api} 要求您每小时重新登录一次，以保持连接。',
		everyDay: '{api} 要求您每天重新登录一次，以保持连接。',
		everyHours: {
			other: '{api} 要求您每 {count} 小时重新登录一次，以保持连接。'
		},
		everyDays: {
			other: '{api} 要求您每 {count} 天重新登录一次，以保持连接。'
		}
	},

	codeRequired: {
		headingApp: '{app} 需要两步登录',
		headingAny: '您要登录的应用需要两步登录',
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
		returnAny: '不登录，返回应用',
		passkey: '使用通行密钥登录',
		passkeyHeldApp: '您有 {email} 的通行密钥。用它登录即可打开 {app}。',
		passkeyHeldAny: '您有 {email} 的通行密钥。用它登录即可继续。'
	},

	passkeyOffer: {
		heading: '下次登录更快',
		explain:
			'为 {email} 创建一个通行密钥。下次登录{service}时，您可以使用指纹、面容或屏幕锁，无需输入密码。',
		where:
			'您的通行密钥保存在此设备或您的密码管理器中。您的密码也仍然可以使用。',
		create: '创建通行密钥',
		notNow: '以后再说',
		never: '不再询问',
		cancelled: '通行密钥未创建。您可以重试，或选择“以后再说”。',
		exists: '此设备上已有您账户的通行密钥。',
		needsScript: '创建通行密钥需要 JavaScript。',
		failed: '无法创建通行密钥。您可以重试，或选择“以后再说”。',
		createdHeading: '通行密钥已创建',
		created:
			'下次登录{service}时，请选择您的通行密钥。我们已向 {email} 发送确认邮件。',
		createdConditional:
			'我们已向 {email} 发送一封邮件。请在此浏览器中打开它，并选择“是的，是我本人”以完成设置。',
		continueApp: '继续前往 {app}',
		continueAny: '继续',
		campaignHeading: '为{service}创建通行密钥',
		campaignExplain:
			'{service}希望所有人为 {email} 设置通行密钥。在关闭密码登录之前，您的密码仍可使用。',
		campaignSkip: '暂时跳过（剩余 {left}/{total} 次）',
		campaignMandatory: '跳过次数已用完。请立即创建通行密钥以继续。',
		campaignUnsupported:
			'此设备无法创建通行密钥。下次请使用手机或其他支持通行密钥的设备登录。',
		campaignContinueThisTime: '本次继续',
		campaignUnverified:
			'创建通行密钥之前，请先验证您的电子邮件地址（{email}）。'
	},

	passkeyRegister: {
		title: '使用通行密钥注册',
		heading: '使用通行密钥创建您的{service}账户',
		withPasskey: '使用通行密钥注册',
		passwordInstead: '改为设置密码',
		emailLabel: '电子邮件地址',
		continueButton: '使用通行密钥继续',
		sentHeading: '请查看您的邮箱',
		sentLink:
			'我们已向 {email} 发送了注册链接。请在 10 分钟内在此浏览器中打开它以创建通行密钥。',
		sentCode:
			'我们已向 {email} 发送了 6 位验证码。请在 10 分钟内在下方输入以创建通行密钥。',
		codeLabel: '6 位验证码',
		codeVerify: '继续',
		codeInvalid: '验证码无效。请查看邮件后重试。',
		codeTooMany: '错误次数过多。请重新开始注册。',
		createHeading: '创建您的通行密钥',
		createHint:
			'您的邮箱（{email}）已确认。请在此设备或密码管理器中保存通行密钥以完成注册。',
		createButton: '创建通行密钥',
		unsupported:
			'此设备无法创建通行密钥。请在手机或其他支持通行密钥的设备上打开此页面。',
		unavailable: '由于未配置邮件发送，通行密钥注册暂时不可用。',
		duplicate: '该电子邮件地址已注册。请返回登录页面访问您的账户。',
		invalidLink: '此注册链接已失效。请在此浏览器中重新开始注册。',
		backToSignIn: '返回登录'
	},

	passkeyRecovery: {
		title: '恢复您的通行密钥',
		heading: '丢失了通行密钥？',
		intro:
			'输入您的电子邮件地址。如果您的账户符合条件，我们将发送一个 10 分钟内仅在此浏览器有效的恢复链接。',
		submit: '发送恢复链接',
		sentHeading: '请查看您的邮箱',
		sentHint:
			'如果 {email} 存在符合条件的账户，我们已发送恢复链接。请在 10 分钟内在此浏览器中打开它。',
		invalidLink: '此恢复链接已失效。请在此浏览器中重新申请。',
		totpHeading: '使用身份验证器应用确认',
		totpHint: '添加新的通行密钥之前，请输入身份验证器应用中的 6 位验证码。',
		totpLost: '通行密钥和身份验证器应用都丢失了？请联系管理员获取帮助。',
		totpButton: '继续',
		createHeading: '添加新的通行密钥',
		createHint: '为 {email} 创建新的通行密钥。您原有的通行密钥会保留。',
		createButton: '创建新通行密钥',
		doneHeading: '您的新通行密钥已就绪',
		doneHint: '新的通行密钥已添加。出于安全考虑，请使用通行密钥登录以继续。',
		signInButton: '使用通行密钥登录'
	},

	passkeyRequired: {
		headingApp: '{app} 要求您使用通行密钥登录',
		headingApi: '{api} 要求您使用通行密钥登录',
		headingAny: '您要登录的应用要求您使用通行密钥登录',
		explain: '通行密钥让您用指纹、面容或屏幕锁登录，而且仿冒网站无法使用它。',
		held: '您的账号 {email} 有通行密钥。用它登录即可继续。',
		notConfirmed:
			'您的通行密钥尚未确认。请在此浏览器中打开关于它的邮件并选择“是的，是我本人”，然后在这里用它登录。',
		none: '您的账号 {email} 还没有通行密钥。',
		ask: '您无法在这里创建通行密钥。请联系 {service} 的管理员。',
		device:
			'此次登录是通过另一台设备上显示的验证码发起的。通行密钥登录必须在应用自己的浏览器中进行，因此这次登录无法打开它。',
		signIn: '使用通行密钥登录',
		create: '创建通行密钥',
		cancelled: '通行密钥未创建。您可以重试。',
		exists: '此设备上已有您账户的通行密钥。',
		failed: '无法创建通行密钥。您可以重试。',
		needsScript: '创建通行密钥需要 JavaScript。',
		createdFull: '通行密钥已创建。用它登录即可继续。',
		createdConditional:
			'通行密钥已创建。我们已向 {email} 发送一封邮件。请在此浏览器中打开它并选择“是的，是我本人”，然后在这里用通行密钥登录。'
	},

	errors: {
		invalidCredentials: '用户名或密码无效',
		invalidCode: '验证码无效',
		codeJustUsed: '此验证码刚刚已被使用。请等待下一个验证码。',
		passwordsDiffer: '两次输入的密码不一致',
		mailLimited: '您的网络在过去一小时内请求的邮件过多。请稍后再试。',
		passwordTooShort: {
			other: '请至少使用{count}个字符。'
		},
		verificationSent: '我们已向{email}发送了验证链接。请打开该链接，然后登录。',
		verificationOutstanding:
			'登录前，请先验证您的电子邮件地址。请打开我们发送到{email}的链接。',
		verificationRecent: '最近已发送过验证邮件。请查看收件箱。',
		verificationUnsent: '我们无法发送验证邮件。请稍后重试。',
		passkeyRefused:
			'此通行密钥不适用于 {service}。请选择其他通行密钥，或使用其他方式登录。',
		passkeyAccount: '此账号目前无法登录。请联系 {service} 的管理员。',
		passkeyLimited:
			'您的网络尝试使用通行密钥登录的次数过多。请稍后再试，或使用其他方式登录。'
	}
};
