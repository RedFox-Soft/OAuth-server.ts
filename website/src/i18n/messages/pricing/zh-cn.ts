import type english from './en.ts';

export const source = 'c9b677540e41';

export default {
	title: '定价',
	description:
		'在 FoxAuth Cloud 上免费开始，或免费自托管完整服务器。付费云方案正在开发中，另提供企业支持。',
	eyebrow: '定价',
	heading: '免费开始：在我们的云上，或在你自己的服务器上。',
	lead: '在 FoxAuth Cloud 创建免费账户，几分钟内就能拥有一个可用的授权服务器；或者自己运行同一个服务器，功能完整、没有限制。付费云方案正在开发中，将提供更高的限额和保障。',
	cloudFree: {
		badge: '现已可用',
		name: 'Cloud Free',
		price: '免费',
		tagline: '我们在 auth.foxauth.dev 上运行的实例。无需信用卡，无需电话。',
		items: [
			'每位管理员 2 个项目，每个项目都是独立的 OpenID Connect 签发者',
			'每个项目每月 1,000,000 名活跃用户',
			'每个项目 10 个应用和 10 个 API',
			'通过 Google、Apple、GitHub 和任意组织的 Microsoft 账户登录',
			'服务间令牌、设备登录、DPoP 和 PAR，以及 AI 智能体通过 MCP 进行管理',
			'通过 GitHub issues 获得社区支持；暂无 SLA'
		],
		cta: '创建免费账户'
	},
	selfHosted: {
		badge: '现已可用',
		name: '自托管',
		price: '免费',
		tagline: '你的基础设施，你的数据库，无需在我们这里开账户。',
		items: [
			'全部功能，无需在不同版本之间挑选',
			'用户、项目、应用和令牌数量不限',
			'以 FSL-1.1-ALv2 许可源码可用',
			'通过 GitHub issues 获得社区支持'
		],
		cta: '快速开始'
	},
	cloud: {
		badge: '开发中',
		name: '付费云方案',
		price: '尚未定价',
		tagline: '同一个实例，更多空间，并有人对它负责。',
		items: [
			'更多项目、应用和用户',
			'通过任意 OpenID 提供方登录，包括单个组织的 Microsoft 目录',
			'自定义项目地址和自己的域名',
			'SLA 和支持邮箱'
		]
	},
	enterprise: {
		badge: '按协议',
		name: '企业支持',
		price: '面议',
		tagline: '自托管，背后有支持合同兜底。',
		items: [
			'你自行托管，我们为你提供后援',
			'针对缺陷的响应时间 SLA',
			'在公开披露之前收到安全公告',
			'架构评审和优先修复'
		]
	},
	faqEyebrow: '常见问题',
	faqHeading: '每次都会被问到的四个问题。',
	faq: [
		{
			question: '它是开源的吗？',
			answer:
				'FoxAuth 以 FSL-1.1-ALv2 许可发布，属于源码可用（source-available），并非开源许可。你可以阅读、修改、自托管和再分发代码，也可以围绕它开展业务。唯一不允许的是把它作为竞争性的托管服务提供给他人。每个版本发布两年后，该版本即转为 Apache License 2.0，因此这项限制会按公开的时间表到期，不由我们自行决定。'
		},
		{
			question: '现在就能用于生产环境吗？',
			answer:
				'FoxAuth 现在就可以自托管用于生产环境。免费云方案暂时没有 SLA，适合用来起步，还不适合依赖。当前版本是 1.2.0。从首个稳定版本 1.0.0 起，HTTP 接口和管理 API 只会在主版本中做不兼容的变更。升级前请阅读更新日志；如果其中提到无法撤销的迁移，请先做备份，升级后再运行 setup 和 migrate 步骤。协议端点遵循规范，因此为 FoxAuth 编写的客户端实际上是按 RFC 编写的，换到其他服务器时应该只需很少的改动。'
		},
		{
			question: '免费云方案真的免费吗？',
			answer:
				'FoxAuth Cloud 的免费方案不收取任何费用，也不需要信用卡。它提供 2 个项目、每个项目每月 1,000,000 名活跃用户、每个项目 10 个应用和 10 个 API，以及通过 Google、Microsoft、Apple 和 GitHub 登录。达到用户上限时，只会暂停新用户注册，已有账户的人不会被拒绝登录。它暂时没有 SLA。提供更高限额和保障的付费方案正在开发中；加入候补名单不需要承担任何义务，方案开放时我们只会给你发一封邮件。'
		},
		{
			question: '你们提供咨询服务吗？',
			answer:
				'我们提供围绕 FoxAuth 的咨询服务：集成工作、威胁建模，以及面向受监管部署的安全规范一致性。告诉我们你的部署情况，我们会告诉你我们是否是合适的人选。'
		}
	],
	readLicense: '阅读许可证',
	contactUs: '联系我们'
} satisfies typeof english;
