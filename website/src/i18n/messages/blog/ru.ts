import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '1d6ecebb6173';

const plural = new Intl.PluralRules('ru');

function days(count: number): string {
	const form = plural.select(count);
	if (form === 'one') return `${count} день`;
	if (form === 'few') return `${count} дня`;
	return `${count} дней`;
}

export default {
	eyebrow: 'Блог',
	index: {
		heading: 'OAuth на практике',
		description:
			'Заметки об OAuth 2.1, OpenID Connect и собственном сервере авторизации от команды FoxAuth — о том, что по ходу работы стоило записать.',
		lead: 'Что мы узнали, пока строили сервер авторизации, — записано по горячим следам. Решения по протоколу, ловушки, стоившие нам целого дня, и вопросы эксплуатации, на которые справочная документация не отвечает.',
		subscribe: (feed: string, guide: string) =>
			rich(
				'Подпишитесь на ',
				{ link: 'RSS-ленту', href: feed },
				' или откройте ',
				{ link: 'руководство по началу работы', href: guide },
				', если вам интереснее попробовать, чем читать.'
			),
		emptyHeading: 'Пока ничего не опубликовано',
		emptyBody:
			'Первая статья ещё пишется. А пока о том, как запустить сервер, рассказывает документация, а о том, что уже вышло, — журнал изменений.',
		readDocs: 'Читать документацию',
		seeShipped: 'Что уже вышло',
		updated: (date: string) => ` · обновлено ${date}`
	},
	post: {
		by: 'Автор:',
		updated: ' · обновлено ',
		storageScope: (backend: string) =>
			`Эта статья посвящена именно бэкенду ${backend}. Сервер работает не с одним хранилищем, и в некоторых местах остальные ведут себя иначе.`,
		agedHeading: 'Стоит перепроверить.',
		aged: (count: number) =>
			` Последний раз статья правилась ${days(count)} назад, а сервер с тех пор изменился. Описанное поведение может быть уже неактуальным — актуальна документация.`,
		allArticles: 'Все статьи',
		tryIt: 'Попробовать самому'
	},
	feed: {
		title: 'Блог FoxAuth',
		description:
			'Заметки об OAuth 2.1, OpenID Connect и собственном сервере авторизации от команды FoxAuth — о том, что по ходу работы стоило записать.'
	}
} satisfies typeof english;
