import type english from './en.ts';

export const source = '8d758ccd7a30';

export default {
	title: '定价',
	description:
		'自托管 FoxAuth 免费且功能完整。托管云实例正在规划中，自托管部署还可以签订企业支持合同。',
	eyebrow: '定价',
	heading: '运行免费。想让我们担起责任，才需付费。',
	lead: '服务器只有一个构建版本，包含全部功能。你可以付费购买的是托管实例或支持合同。没有任何功能只留给付费方案。',
	selfHosted: {
		badge: '现已可用',
		name: '自托管',
		price: '免费',
		tagline: '你的基础设施，你的数据库，无需在我们这里开账户。',
		items: [
			'全部功能，无需在不同版本之间挑选',
			'用户、客户端、项目和令牌数量不限',
			'以 FSL-1.1-ALv2 许可源码可用',
			'通过 GitHub issues 获得社区支持'
		],
		cta: '快速开始'
	},
	cloud: {
		badge: '即将推出',
		price: '尚未定价',
		tagline: '同一个服务器，由编写它的人来运行。',
		items: [
			'托管实例，使用你自己的域名',
			'备份和升级由我们负责',
			'SLA 和支持邮箱',
			'数据留在你选择的区域'
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
				'FoxAuth 现在就可以自托管用于生产环境。当前版本是 0.9.0；0.x 版本意味着 HTTP 接口和管理 API 在次版本之间仍可能变化。升级前请阅读更新日志；如果其中提到无法撤销的迁移，请先做备份，升级后再运行 setup 和 migrate 步骤。协议端点遵循规范，因此为 FoxAuth 编写的客户端实际上是按 RFC 编写的，换到其他服务器时应该只需很少的改动。'
		},
		{
			question: '加入云服务候补名单需要承担什么义务？',
			answer:
				'加入云服务候补名单不需要承担任何义务。我们会保存你的邮箱地址，在托管版 FoxAuth 实例开放时给你发一封邮件；如果你提出要求，我们就删除它。目前还没有需要你同意的价格。'
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
