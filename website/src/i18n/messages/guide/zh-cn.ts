import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '3ddaf19b1c97';

export default {
	title: '你需要什么？',
	description:
		'回答两个问题，看看哪种登录方案适合你：每一步发生什么、用户看到什么，以及一键完成设置的按钮。',
	lead: '回答两个关于你的产品的问题，或者选出你的客户公司提出的要求。下面的答案会一步一步说明发生了什么。一个按钮就能在 FoxAuth Cloud 上你的项目里完成设置。',
	tabs: {
		legend: '指南的哪一部分',
		product: '你的产品：为用户和智能体提供登录',
		productShort: '你的产品',
		enterprise: '你的客户是一家公司（企业）',
		enterpriseShort: '企业'
	},
	questions: {
		first: '谁在操作？',
		moreTasks: '更多常见任务',
		moreTasksSub: '它们不是登录流程，但往往是你接下来需要的。',
		pickSecond: '在第 2 个问题中选一个答案，它就会显示在这里。',
		backToQuestions: rich('这里显示的是你选的任务。', {
			link: '重新显示两个问题的答案',
			href: '#g-panel-product'
		}),
		agentNative: rich(
			'智能体是否运行在用户的电脑上，并以用户的身份登录？这和',
			{ link: '桌面或终端里的应用', href: '#answer-native' },
			'是同一种情况。'
		)
	},
	enterprise: {
		tag: '你的客户公司',
		heading: '当你的客户是一家公司：他们的 IT 部门会提出什么要求',
		lead: '普通应用完全不需要这些。选出这家公司提出的要求。',
		together: '公司登录和 SCIM 排在最前面。它们通常一起出现。',
		togetherTag: '通常一起出现',
		legend: '这家公司要求什么？',
		picture: {
			employees: '员工',
			directory: '公司目录',
			idp: 'Okta 或 Entra ID',
			yourApp: '接入 FoxAuth 的你的应用'
		}
	},
	answer: {
		persona: {
			person: '用户',
			program: '程序',
			agent: 'AI 智能体',
			enterprise: '企业'
		},
		marks: {
			ready: 'FoxAuth Cloud 上已可用',
			ownServer: '在你自己的服务器上',
			notOnFree: 'Free 方案不包含'
		},
		setUp: '立即设置',
		destination: '在 FoxAuth Cloud 中打开，进入你的项目。',
		destinationSub: '你需要先登录，或者创建一个免费账户。',
		ownServerFlag: 'FoxAuth Cloud 关闭了这项功能。',
		ownServerSuper:
			'这需要超级管理员，而 FoxAuth Cloud 上没有超级管理员。在你自己的服务器上，由超级管理员来设置。',
		runOwnServer: rich('如何运行你自己的服务器：', {
			link: '使用 Docker Compose 运行',
			href: '/zh-cn/docs/get-started/docker-compose/'
		}),
		notOnFree:
			'FoxAuth Cloud 的 Free 方案不包含这项功能。付费方案正在开发中，而你自己的服务器现在就能用。',
		seePlans: '查看方案',
		selfHostedFlags: '在你自己的服务器上，请在 Settings 中开启：',
		selfHostedAnyOf: '在你自己的服务器上，请在 Settings 中开启以下任意一项：',
		selfHostedNone: '在你自己的服务器上，这不需要开启任何设置。',
		switchFlags: '请在 Settings 中开启：',
		switchAnyOf: '请在 Settings 中开启以下任意一项：',
		alsoAnyOf: '再开启以下任意一项：',
		and: '和',
		or: '或',
		steps: '逐步了解它如何运作',
		replay: '重新播放步骤',
		sees: '用户会看到什么',
		goodToKnow: '注意事项',
		underTheHood: '底层协议：',
		prompt: '给你的智能体的提示词',
		promptNote:
			'把它粘贴到 Claude、Cursor 或其他编程智能体中。它涵盖你的代码和控制台中的设置。提示词是英文的。',
		copy: '复制提示词',
		copied: '已复制',
		copyFailed: '浏览器不允许复制。请选中文字后手动复制。'
	},
	mini: {
		signIn: {
			heading: '登录你的应用',
			email: '电子邮件地址',
			password: '密码',
			submit: '登录',
			provider: '使用 Google 登录'
		},
		consent: {
			heading: '你的应用请求访问',
			body: '它将代表你进行操作。',
			deny: '拒绝',
			allow: '允许'
		},
		deviceCode: {
			heading: '输入屏幕上显示的代码',
			code: 'WDJB-MJHT',
			submit: '下一步'
		},
		approve: {
			heading: '批准这个请求？',
			body: '谁在请求，请求什么。',
			decline: '拒绝',
			approve: '批准'
		}
	},
	legend: {
		heading: '如何阅读示意图',
		summary: '显示图例',
		fox: 'FoxAuth 始终是带颜色的方框。',
		plain: '普通方框是你、你的代码或用户。',
		outside: '虚线方框是你无法控制的服务，或者你的客户公司。',
		redirect: '虚线箭头表示把用户的浏览器转到另一个地址。',
		token: '粗箭头表示携带令牌。',
		refusal: '红色虚线箭头表示拒绝。',
		self: '画在一个方框内部的步骤就在那里完成，不发送任何消息。',
		numbers: '步骤都有编号。每张图下方的列表用文字说明同样的内容。'
	},
	all: {
		heading: '所有场景',
		summary: '显示所有场景',
		caption:
			'指南中的每个场景、它背后的协议，以及 FoxAuth Cloud 能否完成设置。',
		situation: '场景',
		protocol: '底层协议',
		mark: '在 FoxAuth Cloud 上',
		product: '你的产品',
		enterprise: '企业'
	},
	nothingFits: {
		heading: '都不合适？那就自己配置一切',
		body: '每个应用都可以手动设置。控制台的完整表单按照协议的叫法列出每个字段，没有任何预设。',
		firstClient: '注册你的第一个应用',
		settings: '阅读设置参考'
	}
} satisfies typeof english;
