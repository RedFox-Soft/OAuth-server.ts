import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '65d0584e2611';

export default {
	skipToContent: 'Перейти к содержанию',
	nav: {
		features: 'Возможности',
		pricing: 'Цены',
		compare: 'Сравнение',
		blog: 'Блог',
		docs: 'Документация',
		changelog: 'Изменения',
		github: 'GitHub'
	},
	startFree: 'Начать бесплатно',
	ariaMain: 'Основная навигация',
	ariaMenu: 'Меню',
	ariaMainMenu: 'Главное меню',
	ariaLanguage: 'Язык',
	footer: {
		product: 'Продукт',
		cloud: 'FoxAuth Cloud',
		docs: 'Документация',
		project: 'Проект',
		contact: 'Контакты',
		features: 'Возможности',
		pricing: 'Цены',
		compare: 'Сравнение',
		blog: 'Блог',
		getStarted: 'Начало работы',
		deploy: 'Развёртывание',
		reference: 'Справочник',
		github: 'GitHub',
		changelog: 'История изменений',
		security: 'Безопасность',
		license: 'Лицензия',
		feed: 'RSS-лента блога',
		llms: 'Для LLM (llms.txt)',
		contactUs: 'Написать нам',
		about:
			'FoxAuth построен на OAuth-server.ts, сервере OAuth 2.1 / OpenID Connect.',
		siteVersion: (
			lastTag: string | null,
			commit: string,
			unreleased: boolean
		): string =>
			!unreleased && lastTag
				? `Версия сайта ${lastTag}`
				: lastTag
					? `Версия сайта ${lastTag} + невыпущенные изменения (${commit})`
					: `Версия сайта: не выпущена (${commit})`
	},
	compareLinks: {
		before:
			'Если вы уже используете другое решение, у нас есть сравнения FoxAuth с',
		after:
			', с датой проверки и источниками. В каждом указано, какие страницы мы прочитали и когда.'
	},
	englishOnly: 'Страница доступна только на английском',
	staleTranslation: (href: string) =>
		rich(
			{ strong: 'Английская версия новее.' },
			' Этот перевод сделан с более ранней редакции страницы, и в нём может не хватать изменений, внесённых с тех пор. ',
			{ link: 'Читать английскую версию', href },
			'.'
		),
	breadcrumbs: {
		home: 'Главная',
		docs: 'Документация',
		'get-started': 'Начало работы',
		deploy: 'Развёртывание',
		reference: 'Справочник',
		compare: 'Сравнение',
		blog: 'Блог'
	},
	sections: {
		'Start here': 'С чего начать',
		Product: 'Продукт',
		Compare: 'Сравнение',
		Blog: 'Блог',
		Documentation: 'Документация',
		Reference: 'Справочник',
		Project: 'Проект'
	}
} satisfies typeof english;
