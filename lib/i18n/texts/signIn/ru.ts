import type { SignInTexts } from './index.js';

export const ru: SignInTexts = {
	titles: {
		login: 'Вход',
		registration: 'Регистрация',
		totpEnroll: 'Настройка аутентификатора',
		totpVerify: 'Двухэтапная проверка'
	},

	headings: {
		login: 'Вход в аккаунт {service}',
		loginToApp: 'Вход в {app}',
		registration: 'Создайте аккаунт {service}',
		registrationForApp: 'Регистрация в {app}'
	},

	login: {
		emailRequired: 'Введите адрес электронной почты',
		emailPlaceholder: 'Электронная почта',
		passwordRequired: 'Введите пароль',
		passwordPlaceholder: 'Пароль',
		remember: 'Запомнить меня',
		forgotPassword: 'Забыли пароль?',
		submit: 'Войти',
		registerPrompt: '{link}',
		register: 'Зарегистрироваться',
		resendLink: 'Отправить ссылку ещё раз',
		providersDivider: 'или',
		moreProviders: 'Другие способы входа',
		signInWith: 'Войти через {provider}'
	},

	registration: {
		emailRequired: 'Введите адрес электронной почты',
		emailInvalid: 'Введите правильный адрес электронной почты',
		emailPlaceholder: 'Электронная почта',
		passwordRequired: 'Введите пароль',
		passwordPlaceholder: 'Пароль',
		confirmRequired: 'Повторите пароль',
		confirmMismatch: 'Пароли не совпадают',
		confirmPlaceholder: 'Повторите пароль',
		submit: 'Зарегистрироваться',
		loginPrompt: 'Уже есть аккаунт? {link}',
		login: 'Войти'
	},

	totp: {
		enrollHeading: 'Настройте аутентификатор',
		verifyHeading: 'Двухэтапная проверка',
		enrollHint:
			'Отсканируйте этот QR-код в приложении-аутентификаторе. Затем введите код, который оно покажет.',
		verifyHint: 'Введите текущий код из приложения-аутентификатора.',
		manualKey: 'Или введите этот ключ вручную:',
		codeRequired: 'Введите код',
		confirm: 'Подтвердить',
		verify: 'Проверить'
	},

	notices: {
		verify:
			'Проверьте почту: мы отправили вам ссылку для подтверждения адреса. Войти можно будет после того, как вы её откроете.',
		federationAborted:
			'Вход через внешний сервис не завершён. Попробуйте ещё раз или войдите с паролем.',
		verifyResent:
			'Мы отправили вам новую ссылку для подтверждения. Перейдите по ней, а затем войдите.',
		verifyRecent:
			'Мы недавно уже отправили письмо для подтверждения. Проверьте почту или попробуйте снова через минуту.',
		verifyUnsent:
			'Не удалось отправить письмо для подтверждения. Попробуйте позже.',
		federationLink:
			'Аккаунт с этим адресом электронной почты уже существует. Войдите в него один раз с паролем, чтобы связать его с внешним сервисом входа.'
	},

	errors: {
		invalidCredentials: 'Неверное имя пользователя или пароль',
		invalidCode: 'Неверный код',
		passwordsDiffer: 'Пароли не совпадают',
		passwordTooShort: {
			one: 'Пароль должен содержать минимум {count} символ.',
			few: 'Пароль должен содержать минимум {count} символа.',
			many: 'Пароль должен содержать минимум {count} символов.',
			other: 'Пароль должен содержать минимум {count} символа.'
		},
		verificationSent:
			'Мы отправили ссылку для подтверждения на {email}. Перейдите по ней, а затем войдите.',
		verificationOutstanding:
			'Перед входом подтвердите адрес электронной почты. Перейдите по ссылке, которую мы отправили на {email}.',
		verificationRecent:
			'Мы недавно уже отправили письмо для подтверждения. Проверьте почту.',
		verificationUnsent:
			'Не удалось отправить письмо для подтверждения. Попробуйте позже.'
	}
};
