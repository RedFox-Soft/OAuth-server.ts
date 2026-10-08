import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '26c44358d86b';

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
				' и расскажите, как устроено ваше развёртывание и какие гарантии вам нужны. Мы отвечаем в течение двух рабочих дней.'
			)
	},
	waitlist: {
		join: 'Записаться в лист ожидания',
		reassurance:
			'Вы получите одно письмо, когда облако откроется, и больше ничего. Никаких обязательств.',
		fallback: (address: string, href: string) =>
			rich(
				'Напишите нам на ',
				{ link: address, href },
				', чтобы записаться в лист ожидания. Вы получите одно письмо, когда облако откроется; никаких обязательств.'
			)
	}
} satisfies typeof english;
