import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '1425ed4a7105';

export default {
	skipToContent: '跳到正文',
	nav: {
		features: '功能',
		pricing: '定价',
		compare: '对比',
		blog: '博客',
		docs: '文档',
		changelog: '更新日志',
		github: 'GitHub'
	},
	getStarted: '快速开始',
	ariaMain: '主导航',
	ariaMenu: '菜单',
	ariaMainMenu: '主菜单',
	ariaLanguage: '语言',
	footer: {
		product: '产品',
		docs: '文档',
		project: '项目',
		contact: '联系',
		features: '功能',
		pricing: '定价',
		compare: '对比',
		blog: '博客',
		getStarted: '快速开始',
		deploy: '部署',
		reference: '参考',
		github: 'GitHub',
		changelog: '更新日志',
		security: '安全',
		license: '许可证',
		feed: '博客订阅（RSS）',
		llms: '面向 LLM（llms.txt）',
		contactUs: '联系我们',
		about:
			'FoxAuth 构建于 OAuth-server.ts 之上，这是一个源码可用的 OAuth 2.1 / OpenID Connect 服务器。',
		siteVersion: (version: string, unreleased: boolean): string =>
			`网站版本 ${version}${unreleased ? '（未发布）' : ''}`
	},
	compareLinks: {
		before: '已经在用别的方案？我们维护着与',
		after: ' 的对比，均注明日期和出处，并列出我们查阅过的页面及查阅日期。'
	},
	englishOnly: '此页面仅提供英文版',
	staleTranslation: (href: string) =>
		rich(
			{ strong: '英文原文已有更新。' },
			'本译文基于该页面较早的版本，可能缺少此后的改动。',
			{ link: '阅读英文版', href },
			'。'
		),
	breadcrumbs: {
		home: '首页',
		docs: '文档',
		'get-started': '快速开始',
		deploy: '部署',
		reference: '参考',
		compare: '对比',
		blog: '博客'
	},
	sections: {
		'Start here': '从这里开始',
		Product: '产品',
		Compare: '对比',
		Blog: '博客',
		Documentation: '文档',
		Reference: '参考',
		Project: '项目'
	}
} satisfies typeof english;
