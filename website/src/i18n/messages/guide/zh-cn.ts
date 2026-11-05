import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = 'ad08f33f804e';

export default {
	title: '你需要什么？',
	description:
		'回答两个问题，看看哪种登录方案适合你：每一步发生什么、用户看到什么，以及一键完成设置的按钮。',
	lead: '两个问题，一张图，一个按钮帮你完成设置。',
	tabs: {
		legend: '指南的哪一部分',
		product: '你的产品',
		productSub: '为用户和智能体提供登录',
		enterprise: '企业',
		enterpriseSub: '你的客户是一家公司'
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
	status: {
		ready: 'Cloud 上可用',
		ownServer: '自己的服务器',
		notOnFree: '付费方案'
	},
	strip: {
		label: '问题、解决办法和你得到的结果',
		problem: '你的问题',
		fix: '用上 FoxAuth',
		get: '你会得到什么'
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
		ownServerFlag: 'FoxAuth Cloud 关闭了这项功能。你自己的服务器上可以使用。',
		ownServerSuper:
			'这需要超级管理员，而 FoxAuth Cloud 上没有超级管理员。在你自己的服务器上，由超级管理员来设置。',
		ownServerRoute: '运行你自己的服务器',
		notOnFree:
			'FoxAuth Cloud 的 Free 方案不包含这项功能。付费方案正在开发中，而你自己的服务器现在就能用。',
		seePlans: '查看方案',
		requestPlan: '申请付费方案',
		next: '下一步：',
		selfHostedFlags: '在你自己的服务器上，请在 Settings 中开启：',
		selfHostedAnyOf: '在你自己的服务器上，请在 Settings 中开启以下任意一项：',
		selfHostedNone: '在你自己的服务器上，这不需要开启任何设置。',
		switchFlags: '请在 Settings 中开启：',
		switchAnyOf: '请在 Settings 中开启以下任意一项：',
		alsoAnyOf: '再开启以下任意一项：',
		and: '和',
		or: '或',
		steps: '逐步了解它如何运作',
		prevStep: '上一步',
		nextStep: '下一步',
		replay: '重新播放',
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
			heading: '登录',
			email: '电子邮件地址',
			password: '密码',
			submit: '登录',
			or: '或',
			provider: '使用 Google 登录'
		},
		signUp: {
			heading: '创建账户',
			submit: '创建账户',
			haveAccount: '已有账户？登录'
		},
		companySignIn: {
			before: '通过 ',
			after: ' 登录'
		},
		consent: {
			heading: '一个应用请求访问',
			body: '它将代表你进行操作。',
			deny: '拒绝',
			allow: '允许'
		},
		agentConsent: {
			asks: '请求代表你进行操作',
			scopes: ['读取你的笔记', '添加新笔记']
		},
		adminConsent: {
			brand: 'FoxAuth 管理后台',
			asks: '请求以你的身份操作',
			scopes: ['查看你的项目和应用', '创建和修改应用']
		},
		serviceConsent: {
			connect: '连接你的账户',
			body: '之后你的智能体就能通过 FoxAuth 代表你使用它。',
			cancel: '取消',
			allow: '连接'
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
		fox: 'FoxAuth',
		outside: '不受你控制',
		proxy: '你的反向代理',
		request: '一条消息',
		redirect: '浏览器被转到别处',
		token: '携带令牌',
		refusal: '拒绝',
		self: '在一个方框内完成'
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
