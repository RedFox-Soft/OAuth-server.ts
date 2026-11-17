import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '59e1195bff59';

export default {
	workEmail: 'Рабочий email',
	emailPlaceholder: 'you@company.com',
	contact: {
		need: 'Что вам нужно?',
		needPlaceholder:
			'Как устроено ваше развёртывание, сроки и какие гарантии вам нужны.',
		send: 'Отправить',
		reassurance: 'Отвечает живой человек, обычно в течение двух рабочих дней.',
		fallback: (address: string, href: string) =>
			rich(
				'Напишите нам на ',
				{ link: address, href },
				' и расскажите, как устроено ваше развёртывание и какие гарантии вам нужны. Обычно мы отвечаем в течение двух рабочих дней.'
			)
	},
	enterprise: {
		name: 'Ваше имя',
		company: 'Компания',
		users: 'Сколько людей будет входить',
		usersPlaceholder: 'около 5 000 в месяц',
		hosting: 'Где должен работать сервер?',
		hostingOptions: {
			shared:
				'FoxAuth Enterprise Cloud, общий только для корпоративных клиентов, с SLA',
			ours: 'Отдельный экземпляр у FoxAuth, только для нас',
			yours: 'На нашей инфраструктуре, с вашей поддержкой',
			unsure: 'Пока не знаем'
		},
		message: 'Что вам нужно?',
		messagePlaceholder: 'Ваш проект, сроки и зачем вам отдельный экземпляр.',
		send: 'Запросить приглашение',
		reassurance: 'Отвечает живой человек, обычно в течение двух рабочих дней.',
		sent: 'Спасибо. Запрос отправлен, и живой человек ответит вам, обычно в течение двух рабочих дней.'
	}
} satisfies typeof english;
