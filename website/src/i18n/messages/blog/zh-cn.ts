import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '1d6ecebb6173';

export default {
	eyebrow: '博客',
	index: {
		heading: 'OAuth 实践',
		description:
			'FoxAuth 团队关于 OAuth 2.1、OpenID Connect 和自行运行授权服务器的笔记，遇到值得记下的事就写下来。',
		lead: '构建授权服务器的过程中学到的东西，趁还记得清楚时写下来：协议层面的决策、让我们耗掉一整天的陷阱，以及参考文档回答不了的运维问题。',
		subscribe: (feed: string, guide: string) =>
			rich(
				'可以通过',
				{ link: '订阅源', href: feed },
				'订阅；如果你更想直接上手而不是读文章，请看',
				{ link: '快速开始指南', href: guide },
				'。'
			),
		emptyHeading: '暂无文章',
		emptyBody:
			'第一篇文章还在写。在此期间，文档介绍了如何运行服务器，更新日志记录了已经发布的内容。',
		readDocs: '阅读文档',
		seeShipped: '查看已发布内容',
		updated: (date: string) => ` · 更新于 ${date}`
	},
	post: {
		by: '作者',
		updated: ' · 更新于 ',
		storageScope: (backend: string) =>
			`本文专门讨论 ${backend} 后端。服务器支持不止一种后端，其他后端在部分地方的行为有所不同。`,
		agedHeading: '值得再核实一下。',
		aged: (days: number) =>
			`本文最后修订于 ${days} 天前，此后服务器已有变化。文中描述的行为可能已不再是现状——请以文档为准。`,
		allArticles: '全部文章',
		tryIt: '亲自试试'
	},
	feed: {
		title: 'FoxAuth 博客',
		description:
			'FoxAuth 团队关于 OAuth 2.1、OpenID Connect 和自行运行授权服务器的笔记，遇到值得记下的事就写下来。'
	}
} satisfies typeof english;
