import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '36cec294b076';

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
			'Заметки команды FoxAuth об OAuth 2.1, OpenID Connect и собственном сервере авторизации. Мы пишем о том, что по ходу работы стоило записать.',
		lead: 'Здесь мы по горячим следам записываем то, что узнали, пока строили сервер авторизации. Статьи рассказывают о решениях по протоколу, о ловушках, стоивших нам целого дня, и о вопросах эксплуатации, на которые справочная документация не отвечает.',
		subscribe: (feed: string, guide: string) =>
			rich(
				'Подпишитесь на ',
				{ link: 'RSS-ленту', href: feed },
				' или откройте ',
				{ link: 'руководство по началу работы', href: guide },
				', если вам интереснее попробовать сервер, чем читать о нём.'
			),
		emptyHeading: 'Пока ничего не опубликовано',
		emptyBody:
			'Первая статья ещё пишется. А пока о том, как запустить сервер, рассказывает документация. Что уже вышло, записано в журнале изменений.',
		readDocs: 'Читать документацию',
		seeShipped: 'Что уже вышло',
		updated: (date: string) => ` · обновлено ${date}`
	},
	post: {
		by: 'Автор:',
		updated: ' · обновлено ',
		storageScope: (backend: string) =>
			`Эта статья посвящена только бэкенду ${backend}. Сервер поддерживает не одно хранилище, и в некоторых местах остальные ведут себя иначе.`,
		agedHeading: 'Стоит перепроверить.',
		aged: (count: number) =>
			` Последний раз статья правилась ${days(count)} назад, а сервер с тех пор изменился. Описанное поведение могло устареть. Актуальное описание есть в документации.`,
		allArticles: 'Все статьи',
		tryIt: 'Попробовать самому'
	},
	feed: {
		title: 'Блог FoxAuth',
		description:
			'Заметки команды FoxAuth об OAuth 2.1, OpenID Connect и собственном сервере авторизации. Мы пишем о том, что по ходу работы стоило записать.'
	}
} satisfies typeof english;
