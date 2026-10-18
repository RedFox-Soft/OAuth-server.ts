import { rich } from '../../types.ts';
import type english from './en.ts';
import type { HomeFacts } from './en.ts';

export const source = 'bd32b9336b38';

export default {
	title: 'FoxAuth — 面向智能体时代的授权服务器',
	description:
		'用户登录、API 与 AI 智能体共用一个 OAuth 2.1 / OIDC 服务器，FoxAuth Cloud 每月免费 100 万活跃用户。',
	hero: {
		eyebrow: 'OAuth 2.1 · OpenID Connect · MCP',
		heading: '一个服务器，服务你的用户、API 和 AI 智能体。',
		lead: '用户登录、企业身份提供商、目录同步、银行级令牌安全，以及 AI 智能体授权：一个团队要花数年才能做完的 30 项标准，这里已经实现并经过测试。在 FoxAuth Cloud 上免费开始，每个项目每月最多 1,000,000 名活跃用户；也可以自己运行。',
		getStarted: '自己运行',
		freeAccount: '创建免费账户',
		github: '在 GitHub 上查看',
		specifications: '30 项规范',
		freeUsers: '1,000,000 MAU 免费',
		quickstartCaption: '两条命令，一个浏览器标签页',
		givesHeading: '这两条命令为你准备好了什么',
		gives: [
			{
				head: '数据库',
				body: '已启动并完成预配，带有索引和一个签名密钥'
			},
			{
				head: '管理控制台',
				body: '位于 /admin，首次运行时引导你设置超级管理员'
			},
			{
				head: '发现文档',
				body: '位于 /.well-known/openid-configuration，反映你设置的功能开关'
			},
			{
				head: '无需账户',
				body: '无需在我们这里开账户，没有 API 密钥，也不用打电话'
			}
		]
	},
	console: {
		eyebrow: '控制台',
		heading: '运维所需的一切，无需第二个产品。',
		lead: '项目及其中的应用和 API、最终用户、上游身份提供商、SCIM 连接、设置、SMTP、签名密钥、月活跃用户，以及只追加的审计日志，全部集中在一个控制台里；登录控制台走的是服务器自身的 OpenID Connect 流程，也可以通过你所在组织的身份提供商登录。可能让人无法登录的更改，会在生效前先告诉你影响到谁。AI 智能体通过 MCP 使用的也是同一套 API。',
		screenshotAlt: 'FoxAuth 管理控制台，列出某个项目的应用（OAuth 客户端）。',
		screenshotCaption:
			'内置控制台中某个项目的应用。这里的每一次更改都会生成一条审计记录。'
	},
	audiences: {
		eyebrow: '谁在运行它',
		heading: '三类团队，同一个服务器。',
		lead: '同一个二进制文件，同一套管理 API。不同之处主要在于你打开了哪些功能开关。',
		seeAll: '查看全部功能',
		cards: [
			{
				title: '面向 TypeScript 团队',
				body: '基于 Bun 和 Elysia，一条命令即可运行；31 个具名扩展点可以直接换成你自己的函数，无需 fork。',
				points: [
					'运行在 Bun 上，HTTP 层是 Elysia',
					({ backends }: HomeFacts) => `生产环境用 ${backends}，测试用内存存储`,
					'31 个覆盖扩展点，在调用时解析'
				]
			},
			{
				title: '面向 AI 智能体开发者',
				body: '用它保护你自己的 MCP 服务器，并让智能体沿着控制台自身的代码路径来管理实例。没有另一套需要同步维护的特权 API。',
				points: [
					'声明你的 MCP 服务器，即可获得受众绑定的令牌（RFC 8707）',
					'支持 Client ID Metadata Documents，智能体宿主无需任何预先配置',
					({ tools }: HomeFacts) =>
						`${tools} 个用于管理的 MCP 工具，设置 mcp.enabled 之前保持关闭`
				]
			},
			{
				title: '面向受监管行业',
				body: '银行级安全规范如今都已实现，没有一项还在等路线图。监管方要求哪个，就打开哪个开关。',
				points: [
					'FAPI、DPoP、PAR、mTLS、CIBA、RAR、JARM',
					'只追加的管理审计日志',
					'按身份的暴力破解节流'
				]
			}
		]
	},
	quickStart: {
		eyebrow: '快速开始',
		heading: '五分钟拿到令牌。',
		lead: '无需在我们这里开账户，也不要 API 密钥。读完三篇短文，你的终端里应该就有一个令牌了。',
		steps: [
			{
				title: '运行服务器',
				body: 'Docker Compose 会启动数据库、预配数据库结构并初始化管理控制台。每种数据存储各有一个文件，任选其一。'
			},
			{
				title: '注册客户端',
				body: '在控制台中创建一个项目及其第一个 OAuth 客户端，并填写精确匹配的重定向 URI。'
			},
			{
				title: '获取令牌',
				body: '走一遍带 PKCE 的授权码流程，并读出 ID 令牌中的声明。'
			}
		]
	},
	standards: {
		eyebrow: '标准',
		heading: '30 项规范，均已实现。',
		lead: '下面每一项都是仓库里的代码，并且有测试。每一项都链接到它所实现的规范；参考文档写明了控制它的功能开关。',
		reference: '端点参考'
	},
	mcp: {
		eyebrow: '为 MCP 打造的 OAuth 服务器',
		heading: '保护你的 MCP 服务器，并让智能体来运维这一台。',
		protect: rich(
			'把你自己的 MCP 服务器声明为某个项目的受保护资源，本服务器就会签发受众恰好是该资源的令牌。这里不用写代码，也不用重启。智能体宿主会发现它、让你的用户登录，然后带着令牌回来；你的 MCP 服务器对照公开的密钥即可验证该令牌，无需向任何一方询问。值为 HTTPS URL 的 ',
			{ code: 'client_id' },
			' 会被当作客户端身份文档接受，因此一个什么都不用配置的宿主也能连上。'
		),
		operate: (tools: number) =>
			rich(
				'打开 ',
				{ code: 'mcp.enabled' },
				' 后，管理 API 会以 OAuth 2.1 受保护资源的形式在 ',
				{ code: 'POST /mcp' },
				` 上提供给 AI 智能体。这 ${tools} 个工具中的每一个都会重建控制台本应发送的请求，并执行控制台自身的权限检查、校验和审计写入，因此不存在会与控制台逐渐脱节的特权后门。`
			),
		confirm:
			'破坏性操作和影响整个实例的操作需要两次调用：第一次返回确认令牌，第二次携带该令牌。此功能默认关闭。',
		protectButton: '保护你的 MCP 服务器',
		allTools: (tools: number) => `全部 ${tools} 个 MCP 工具`
	},
	start: {
		eyebrow: '开始',
		heading: '今天就免费开始。',
		lead: '在 FoxAuth Cloud 创建免费账户，每个项目每月最多 1,000,000 名活跃用户；或者今天下午就自己运行服务器。付费云方案正在开发中。',
		freeAccount: '创建免费账户',
		getStarted: '自己运行',
		docs: '阅读文档'
	}
} satisfies typeof english;
