import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '1425ed4a7105';

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
	getStarted: 'Начать',
	ariaMain: 'Основная навигация',
	ariaMenu: 'Меню',
	ariaMainMenu: 'Главное меню',
	ariaLanguage: 'Язык',
	footer: {
		product: 'Продукт',
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
			'FoxAuth построен на OAuth-server.ts — сервере OAuth 2.1 / OpenID Connect с доступным исходным кодом (source-available).',
		siteVersion: (version: string, unreleased: boolean): string =>
			`Версия сайта ${version}${unreleased ? ' (не выпущена)' : ''}`
	},
	compareLinks: {
		before: 'Уже используете другое решение? Мы ведём датированные сравнения с',
		after: ', и в каждом указано, какие страницы мы прочитали и когда.'
	},
	englishOnly: 'Страница доступна только на английском',
	staleTranslation: (href: string) =>
		rich(
			{ strong: 'Английская версия новее.' },
			' Этот перевод сделан с более ранней редакции страницы, и в нём может не быть того, что изменилось с тех пор. ',
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
