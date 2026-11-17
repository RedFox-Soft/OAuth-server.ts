import type english from './en.ts';

export const source = '63e7d141da54';

export default {
	title: '定价',
	description:
		'FoxAuth Cloud 在测试期间免费，不限用户数。Enterprise 是你自己的独立实例，仅限受邀。',
	eyebrow: '定价',
	heading: '在我们的云上免费。独立实例仅限受邀。',
	lead: 'FoxAuth Cloud 在测试期间免费，不限用户数：创建账户，几分钟内就能拥有一个可用的授权服务器。在测试期间加入的团队，在付费方案推出后还可以再免费使用一年。需要独立实例的公司，可以申请邀请。',
	cloudFree: {
		badge: '测试期间免费',
		name: 'Cloud',
		price: '免费',
		tagline:
			'我们在 auth.foxauth.dev 上运行的实例。无需信用卡，无需电话，不限用户数。',
		items: [
			'每月活跃用户、应用和 API 数量不限',
			'每位管理员最多 10 个项目，每个项目都是独立的 OpenID Connect 签发者，地址由你选择',
			'通过 Google、Apple、GitHub 和 Microsoft 登录，也可以通过任意 OpenID 提供方登录，包括 Okta 或单个组织的 Entra ID',
			'服务间令牌、设备登录、发送方约束令牌（DPoP）、推送授权请求（PAR），以及 AI 智能体通过 MCP 进行管理',
			'可应要求使用你自己的域名',
			'在测试期间加入的团队，付费方案推出后还可免费使用一年',
			'通过 GitHub issues 获得社区支持；暂无 SLA'
		],
		cta: '创建免费账户'
	},
	enterprise: {
		badge: '仅限受邀',
		name: 'Enterprise',
		price: '面议',
		tagline:
			'与免费云分开的 Enterprise Cloud、你自己的独立实例，或你自己的基础设施。仅限受邀。',
		items: [
			'Enterprise Cloud：仅供企业客户共享，与免费云分开，提供 SLA',
			'独立实例，由我们运行或部署在你的基础设施上，其数据库和密钥与其他所有人分开',
			'针对缺陷的响应时间 SLA',
			'在公开披露之前收到安全公告',
			'架构评审和优先修复'
		]
	},
	faqEyebrow: '常见问题',
	faqHeading:
		'每次都会被问到的四个问题：许可证、生产环境使用、免费方案和咨询服务。',
	faq: [
		{
			question: 'FoxAuth 是开源的吗？',
			answer:
				'FoxAuth 以 FSL-1.1-ALv2 许可发布，属于源码可用（source-available），并非开源许可。你可以阅读、修改、自托管和再分发代码，也可以围绕它开展业务。唯一不允许的是把它放进与 FoxAuth 竞争的商业产品或服务中提供给他人，无论是否托管。每个版本发布两年后，该版本即转为 Apache License 2.0，因此这项限制会按公开的时间表到期，不由我们自行决定。'
		},
		{
			question: 'FoxAuth 现在就能用于生产环境吗？',
			answer:
				'FoxAuth 现在就可以自托管用于生产环境。免费云方案暂时没有 SLA，适合用来起步，还不适合依赖。当前版本是 2.0.0。从首个稳定版本 1.0.0 起，HTTP 接口和管理 API 只会在主版本中做不兼容的变更。升级前请阅读更新日志；如果其中提到无法撤销的迁移，请先做备份，升级后再运行 setup 和 migrate 步骤。协议端点遵循规范，因此为 FoxAuth 编写的客户端实际上是按 RFC 编写的，换到其他服务器时应该只需很少的改动。'
		},
		{
			question: 'FoxAuth Cloud 真的免费吗？',
			answer:
				'FoxAuth Cloud 在测试期间免费，也不需要信用卡。每月活跃用户、应用和 API 数量不限，包含每位管理员最多十个项目，每个项目的地址由你选择，并可通过任意 OpenID 提供方登录。少数需要超级管理员的功能，例如开发者自行注册应用，只能在你自己的服务器上运行。自己的域名可应要求设置。在测试期间加入的团队，在付费方案推出后还可以再免费使用一年。目前暂无 SLA。提供 SLA 的付费方案正在开发中。'
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
