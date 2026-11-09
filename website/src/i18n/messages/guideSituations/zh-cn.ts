import type { GuideTexts } from '../../guide-texts.ts';

export const source = '6fffc1f9dca9';

export default {
	questions: {
		person: {
			title: '一个人',
			sub: '登录你的应用',
			second: '你的代码运行在哪里？',
			answers: {
				server: { title: '在服务器上', sub: 'Next.js、Django、Rails、Laravel' },
				spa: { title: '在浏览器中', sub: 'React、Vue、Angular，没有服务器' },
				native: {
					title: '手机、桌面或终端',
					sub: 'iOS、Android、Electron、CLI'
				},
				device: { title: '没有键盘的设备', sub: '电视、机顶盒、自助终端' }
			}
		},
		program: {
			title: '没有人参与的程序',
			sub: '服务、定时任务、你的 API',
			second: '你在构建什么？',
			answers: {
				service: { title: '调用 API 的程序', sub: '后台任务、cron、其他服务' },
				api: { title: '需要保护的 API', sub: '只允许你自己的应用调用' },
				platform: { title: '面向其他开发者的平台', sub: '他们自己注册应用' }
			}
		},
		agent: {
			title: 'AI 智能体',
			sub: 'Claude、Cursor、ChatGPT 或你自己的',
			second: '智能体需要做什么？',
			answers: {
				mcp: {
					title: '连接到我的 MCP 服务器',
					sub: '用户登录后即可连接，无需注册'
				},
				connected: {
					title: '使用用户的 Google、GitHub 等账户',
					sub: '代表用户，并经用户同意'
				},
				adminmcp: { title: '管理 FoxAuth 本身', sub: '通过管理 MCP' }
			}
		}
	},
	situations: {
		server: {
			title: '有自己服务器的网站',
			sentence:
				'你的服务器保存一个密钥，并用一次性授权码换取令牌，所以这是最简单也最安全的登录方式。',
			protocol:
				'OpenID Connect · Authorization Code + PKCE · client_secret_basic · 刷新令牌',
			problemCaption: '你的服务器保存着所有人的密码。',
			fixCaption: '只有 FoxAuth 能看到密码。',
			lanes: { person: '用户', server: '你的服务器', fox: 'FoxAuth' },
			steps: [
				{ label: '点击“登录”', text: '用户在你的网站上点击“登录”。' },
				{
					label: '转到登录页',
					text: '你的服务器把浏览器转到 FoxAuth 的登录页面。'
				},
				{
					label: '登录',
					text: '用户输入密码，或者使用 Google 登录。只有 FoxAuth 能看到密码。'
				},
				{
					label: '一次性授权码',
					text: 'FoxAuth 把用户送回你的回调地址，并附上一个一次性授权码。'
				},
				{
					label: '授权码 + 密钥',
					text: '你的服务器出示自己的密钥，用授权码换取令牌。浏览器始终看不到这一步。'
				},
				{ label: '已登录', text: '你的服务器建立会话，用户登录成功。' }
			],
			sees: [
				'FoxAuth 的登录页面',
				'密码，或身份提供商的按钮',
				'然后回到你的网站，已经登录'
			],
			goodToKnow: [
				'只有 localhost 可以使用普通 http。其他地址都需要 https。',
				'把密钥放在服务器的环境变量中，绝不要写进代码。'
			]
		},
		spa: {
			title: '浏览器中的单页应用',
			sentence:
				'浏览器里没有地方保存密钥，所以由 PKCE 保护登录：它是一个只有当前浏览器标签页知道的一次性校验字符串。',
			protocol:
				'OpenID Connect · Authorization Code + PKCE · 公开应用 · 刷新令牌',
			problemCaption: '浏览器代码里的密钥谁都能看到。',
			fixCaption: '一次性校验取代了密钥。',
			lanes: {
				person: '用户',
				spa: '你的浏览器应用',
				fox: 'FoxAuth',
				api: '你的 API'
			},
			steps: [
				{ label: '点击“登录”', text: '用户在你的应用中点击“登录”。' },
				{
					label: '登录 + PKCE',
					text: '你的应用把浏览器转去登录，并附上校验字符串的指纹。'
				},
				{ label: '登录', text: '用户在 FoxAuth 的页面上登录。' },
				{
					label: '一次性授权码',
					text: 'FoxAuth 把用户送回你的应用，并附上一个一次性授权码。'
				},
				{
					label: '授权码 + 校验字符串',
					text: '你的应用出示校验字符串本身，用授权码换取令牌。没有校验字符串，被盗的授权码毫无用处。'
				},
				{ label: '带令牌调用', text: '你的应用带着访问令牌调用你的 API。' }
			],
			sees: [
				'FoxAuth 的登录页面',
				'密码，或身份提供商的按钮',
				'然后回到你的应用，已经登录'
			],
			goodToKnow: [
				'没有密钥也没关系：由 PKCE 负责保护。',
				'在浏览器中，刷新令牌的有效期比在服务器上更短。',
				'只有 localhost 可以使用普通 http。',
				'如果库能把令牌保存在内存中，就不要把令牌放进 localStorage。'
			]
		},
		native: {
			title: '手机、桌面或终端中的应用',
			sentence:
				'登录在系统浏览器中打开，授权码通过一个本地地址回到你的应用，任何端口都可以。',
			protocol:
				'OpenID Connect · Authorization Code + PKCE · 回环重定向（RFC 8252）',
			problemCaption: '应用能看到用户的密码。',
			fixCaption: '登录在用户信任的浏览器中打开。',
			lanes: { person: '用户', app: '你的应用', fox: 'FoxAuth' },
			steps: [
				{ label: '开始登录', text: '用户点击“登录”，或者运行你的登录命令。' },
				{
					label: '打开浏览器',
					text: '你的应用在系统浏览器中打开登录页面，并带上 PKCE。'
				},
				{ label: '登录', text: '用户在自己信任的浏览器中登录。' },
				{
					label: '授权码发到 127.0.0.1',
					text: 'FoxAuth 把授权码发送到 http://127.0.0.1，端口就是你的应用此刻监听的那个。'
				},
				{ label: '授权码 + PKCE', text: '你的应用用授权码换取令牌。' }
			],
			sees: [
				'系统浏览器中的 FoxAuth 登录页面',
				'然后是你的应用显示的“可以关闭此标签页”'
			],
			goodToKnow: [
				'一个回调地址覆盖所有端口，所以你不必为每次运行单独登记。',
				'没有密钥：应用在用户手中，可以被拆开分析。',
				'运行在用户电脑上、以用户身份登录的 AI 智能体，设置方式完全相同。',
				'不要用嵌入式 WebView 进行登录。'
			]
		},
		device: {
			title: '电视或没有键盘的设备',
			sentence: '设备显示一个简短的代码，用户在手机上登录。',
			protocol: 'OAuth 2.0 Device Authorization Grant (RFC 8628)',
			problemCaption: '要用电视遥控器输入密码。',
			fixCaption: '一个简短的代码，在手机上确认。',
			lanes: { tv: '电视或设备', fox: 'FoxAuth', phone: '用户的手机' },
			steps: [
				{ label: '请求代码', text: '设备向 FoxAuth 请求一个登录代码。' },
				{
					label: '代码 WDJB-MJHT',
					text: 'FoxAuth 返回一个简短的代码和一个地址。设备把两者都显示出来。'
				},
				{
					label: '输入代码并登录',
					text: '用户在手机上打开这个地址，输入代码，然后照常登录。'
				},
				{
					label: '好了吗？',
					text: '与此同时，设备每隔几秒就询问一次代码是否已确认。'
				},
				{ label: '令牌', text: '用户一完成登录，设备就拿到令牌。' }
			],
			sees: [
				'设备上：一个简短的代码和一个地址',
				'手机上：一个输入代码的框，然后是常规登录'
			],
			goodToKnow: [
				'用户需要第二块屏幕：手机或电脑。',
				'代码很短，而且很快过期。不需要存储任何东西。',
				'遵守轮询间隔，并处理 slow_down。'
			]
		},
		service: {
			title: '程序调用你的 API，没有人参与',
			sentence: '程序用自己的 ID 和密钥自行登录，并以自己的名义获得令牌。',
			protocol: 'OAuth 2.1 · Client Credentials',
			problemCaption: '一把永不过期的共享密钥。',
			fixCaption: '短期令牌取代了共享密钥。',
			lanes: { job: '你的程序', fox: 'FoxAuth', api: '你的 API' },
			steps: [
				{ label: 'ID + 密钥', text: '程序出示自己的 ID 和密钥。' },
				{ label: '用于 API 的令牌', text: 'FoxAuth 签发一个访问令牌。' },
				{ label: '带令牌调用', text: '程序带着这个令牌调用你的 API。' },
				{
					label: '校验签名',
					text: '你的 API 用项目的公钥校验令牌的签名。它不会在每次请求时都去询问 FoxAuth。'
				}
			],
			sees: ['没有人看到任何界面：没有用户登录'],
			goodToKnow: [
				'令牌代表程序本身，其中没有任何用户。',
				'如果密钥泄露，就在控制台中签发一个新的。',
				'缓存令牌，直到它过期。不要每次调用都申请新的令牌。'
			]
		},
		api: {
			title: '你的 API 只接受你自己的应用',
			sentence:
				'在项目中声明这个 API，FoxAuth 就会把它作为接收方写进每个令牌，因此发给其他 API 的令牌会被拒绝。',
			protocol:
				'OAuth 2.0 Resource Indicators (RFC 8707) · 绑定受众的令牌 · 内省（RFC 7662）· 撤销（RFC 7009）',
			problemCaption: '你的 API 接受任何令牌。',
			fixCaption: '你的 API 只接受发给自己的令牌。',
			lanes: {
				webapp: '你的应用',
				fox: 'FoxAuth',
				api: '你的 API',
				otherapi: '另一个 API'
			},
			steps: [
				{
					label: '用于你的 API 的令牌',
					text: '你的应用申请令牌，并指明它用于哪个 API。'
				},
				{
					label: '接收方：你的 API',
					text: 'FoxAuth 签发令牌，并在其中写明接收方。'
				},
				{ label: '接受', text: '你的 API 看到接收方是自己，于是接受调用。' },
				{
					label: '拒绝',
					text: '同一个令牌在另一个 API 上会失败：接收方不匹配。'
				}
			],
			sees: ['没有人看到任何界面：这是程序之间的事'],
			goodToKnow: [
				'在一个项目内，API 地址是唯一的。',
				'你的应用在申请令牌时指明 API。',
				'超级管理员开启内省和撤销之后，你的 API 可以向 FoxAuth 询问令牌是否仍然有效，应用也可以撤销不再需要的令牌。',
				'即使签名有效，也要拒绝接收方（aud）不同的令牌。'
			]
		},
		platform: {
			title: '其他开发者在你的平台上注册自己的应用',
			sentence:
				'外部开发者用一个请求自行注册应用，之后用返回的令牌修改或删除它。',
			protocol:
				'Dynamic Client Registration (RFC 7591) · Registration Management (RFC 7592)',
			problemCaption: '你要亲手给每个开发者发密钥。',
			fixCaption: '开发者自己注册应用。',
			lanes: { dev: '其他开发者的应用', fox: 'FoxAuth', person: '用户' },
			steps: [
				{ label: '自行注册', text: '开发者的应用把自己的信息发送到注册地址。' },
				{
					label: 'ID + 管理令牌',
					text: 'FoxAuth 把它保存为一个应用，并返回它的 ID 和一个管理令牌。'
				},
				{
					label: '登录这个应用',
					text: '用户像登录其他应用一样登录它。授权同意页面会说明这个应用是自行注册的。'
				},
				{
					label: '更新或删除',
					text: '之后，应用用管理令牌修改或删除自己的注册信息。'
				}
			],
			sees: ['授权同意页面写出了应用的名称', '页面说明这个应用是自行注册的'],
			goodToKnow: [
				'这是整个服务器的设置，由超级管理员开启。',
				'对于 MCP 客户端，优先使用描述文档地址（metadata URL）：MCP 规范已弃用 MCP 客户端的自行注册。',
				'关闭注册只会阻止新的注册。已经注册的应用照常工作。'
			],
			actionLabel: '打开注册设置'
		},
		mcp: {
			title: 'Claude、Cursor 或 ChatGPT 连接到你的 MCP 服务器',
			sentence:
				'在项目中声明你的 MCP 服务器，用户登录后智能体就能连接，无需注册：智能体用自己描述文档的地址来介绍自己。',
			protocol:
				'MCP Authorization · OAuth 2.1 · Protected Resource Metadata · Client ID Metadata Document',
			problemCaption: '你的 MCP 服务器谁都能访问。',
			fixCaption: '令牌只在你的服务器上有效。',
			lanes: {
				person: '用户',
				agent: 'AI 智能体',
				mcp: '你的 MCP 服务器',
				fox: 'FoxAuth'
			},
			steps: [
				{ label: '连接', text: '智能体尝试连接你的服务器。' },
				{
					label: '401：到 FoxAuth 登录',
					text: '你的服务器回答需要登录，并指明 FoxAuth。'
				},
				{
					label: '介绍自己',
					text: '智能体给出它的描述文档地址（metadata URL）。它事先不注册任何东西。'
				},
				{
					label: '登录并允许',
					text: '用户登录，并看到是哪个智能体在请求访问。'
				},
				{
					label: '用于你的服务器的令牌',
					text: 'FoxAuth 签发一个只对你的服务器有效的令牌。'
				},
				{ label: '调用工具', text: '智能体代表用户使用你的服务器。' }
			],
			sees: [
				'登录页面，然后是授权同意页面',
				'页面写出了智能体和你的 MCP 服务器',
				'用户选择允许或拒绝'
			],
			goodToKnow: [
				'令牌绑定到你的服务器。它在别人的 MCP 服务器上无效。',
				'你的服务器用项目的公钥自行校验令牌。',
				'只有超级管理员在服务器设置中开启这项功能后，智能体才能用描述文档地址介绍自己。无法托管描述文档的智能体需要改为开启注册。',
				'不要在你的 MCP 服务器中自己实现客户端注册。'
			]
		},
		connected: {
			title: '你的智能体在用户的 Google、GitHub 或 Slack 中操作',
			sentence:
				'用户只需连接一次自己的账户。之后智能体通过 FoxAuth 获得访问权限，自己不保存任何人的令牌。',
			protocol: 'OAuth 2.0 Token Exchange (RFC 8693) · 令牌保管库',
			problemCaption: '智能体握着用户的 Google 钥匙。',
			fixCaption: '令牌由 FoxAuth 保管，而不是智能体。',
			lanes: {
				person: '用户',
				agent: 'AI 智能体',
				fox: 'FoxAuth',
				google: 'Google、GitHub、Slack'
			},
			steps: [
				{ label: '连接 Google', text: '用户连接一次自己的账户，并表示同意。' },
				{
					label: '访问权限',
					text: 'Google 授予访问权限。FoxAuth 把它加密保存。'
				},
				{
					label: '交换令牌',
					text: '智能体出示自己的令牌，请求这位用户的 Google 访问权限。'
				},
				{
					label: 'Google 令牌',
					text: 'FoxAuth 交出一个只属于这位用户的 Google 令牌。'
				},
				{
					label: '执行操作',
					text: '智能体以用户的身份读邮件、创建任务或在频道中发消息。'
				}
			],
			sees: [
				'一个写明服务名称的页面，例如 Google',
				'用户连接账户并表示同意',
				'之后，用户能看到自己已连接账户的列表'
			],
			goodToKnow: [
				'你需要在该服务上提供一个应用：它的 ID 和密钥。',
				'用户能看到自己已连接的账户，并可以断开其中任何一个。智能体会立即失去访问权限。',
				'智能体只能拿到连接了该账户的那位用户的令牌。',
				'Google 令牌的保留时间不要超过一次请求。'
			]
		},
		adminmcp: {
			title: '用 AI 智能体管理 FoxAuth',
			sentence:
				'智能体在 FoxAuth 中做的事和你在控制台中做的一样，权限相同，检查相同，没有任何特殊入口。',
			protocol: 'MCP · OAuth 2.1 受保护资源',
			problemCaption: '智能体拿到一把拥有全部权限的密钥。',
			fixCaption: '智能体只拥有你的权限。',
			lanes: { you: '你', agent: 'AI 智能体', fox: 'FoxAuth' },
			steps: [
				{ label: '“创建一个应用”', text: '你用日常语言向智能体提出要求。' },
				{
					label: '管理员登录',
					text: '智能体连接到 /mcp。你登录并允许它代你操作。'
				},
				{
					label: 'client_create',
					text: '智能体调用一个工具：控制台按钮背后也是这个工具。'
				},
				{
					label: '相同的检查',
					text: '权限、检查和方案限额都是控制台自己的那一套。'
				},
				{
					label: '写入审计日志',
					text: '审计日志记录是谁允许的，以及是哪个智能体执行的。'
				},
				{ label: '结果', text: '智能体得到回应，并告诉你完成了什么。' }
			],
			sees: ['管理员登录页面', '一个写明哪个智能体请求以你的身份操作的页面'],
			goodToKnow: [
				'智能体的权限与你的完全相同。',
				'最危险的操作，例如删除项目，仍然只能在控制台中进行。',
				'在超级管理员于服务器设置中开启之前，它处于关闭状态。FoxAuth Cloud 上已经开启。',
				'只有超级管理员允许的智能体才能连接。'
			],
			actionLabel: '打开 MCP 工具'
		},
		social: {
			title: '使用 Google、GitHub、Apple 或 Microsoft 登录',
			sentence:
				'用户用已有的账户登录。你的应用无需任何改动，因为它仍然只与 FoxAuth 通信。',
			protocol: 'OpenID Connect · 联合登录',
			problemCaption: '用户又得想一个新密码。',
			fixCaption: '点一个按钮，用已有的账户登录。',
			lanes: {
				person: '用户',
				webapp: '你的应用',
				fox: 'FoxAuth',
				googleOnly: 'Google'
			},
			steps: [
				{ label: '点击“登录”', text: '用户在你的应用中点击“登录”。' },
				{ label: '转到登录页', text: '你的应用像以前一样把用户转到 FoxAuth。' },
				{ label: '“使用 Google 登录”', text: '用户选择“使用 Google 登录”。' },
				{ label: '询问 Google', text: 'FoxAuth 把用户转到 Google。' },
				{ label: '这是 anna@gmail.com', text: 'Google 确认用户的身份。' },
				{
					label: '照常获得令牌',
					text: '你的应用拿到的令牌与密码登录后的一样。'
				}
			],
			sees: [
				'登录页面为每个提供商显示一个按钮',
				'“使用 Google 登录”',
				'然后是 Google 自己的页面，再返回'
			],
			goodToKnow: [
				'这四个提供商在 Free 方案中都可以使用。',
				'你需要从提供商的控制台获取一个 ID 和一个密钥。',
				'Free 方案中的 Microsoft 登录接受任何组织的账户。如果只允许某一家公司目录中的账户登录，请看面向企业的部分。',
				'你的应用不需要任何改动。'
			]
		},
		behindproxy: {
			title: '没有自带登录的 Web 应用',
			sentence:
				'把应用放在你的代理后面。每个请求到达应用之前，代理都会先询问 FoxAuth。用户登录你的项目，应用本身不需要改动。',
			protocol: 'Forward auth · OpenID Connect · Authorization Code + PKCE',
			problemCaption: '任何知道地址的人都能进入。',
			fixCaption: '你的代理只放行你选定的人。',
			lanes: {
				browser: '用户的浏览器',
				proxy: '你的代理',
				proxied: '你的应用',
				fox: 'FoxAuth'
			},
			steps: [
				{ label: '打开应用', text: '用户打开你的应用。请求先到达你的代理。' },
				{
					label: '询问项目',
					text: '在应用看到请求之前，你的代理先询问项目这个请求能否通过。'
				},
				{
					label: '转到登录页',
					text: '用户还没有登录，所以项目把浏览器转到它的登录页面。'
				},
				{
					label: '登录',
					text: '用户登录项目。如果之前已经登录过，这一步会自动完成。'
				},
				{
					label: '返回 /_foxauth/callback',
					text: '项目把浏览器送回你的应用地址上的 /_foxauth/callback，并在那里设置应用的登录 cookie。'
				},
				{
					label: '是的，这是 Anna',
					text: '在下一个请求中，项目按你为这个路径设置的规则进行检查，然后回答“可以”，并说明这个人是谁。'
				},
				{
					label: '带上 X-Auth-* 请求头',
					text: '你的代理把请求放行到应用，并在 X-Auth-* 请求头中带上用户的 ID、邮箱和用户组。'
				}
			],
			sees: [
				'第一次时，显示项目的登录页面',
				'之后照常打开你的应用',
				'没有权限的人会看到一个说明原因的页面'
			],
			goodToKnow: [
				'确保只能通过你的代理访问应用。绕过代理到达应用的请求不会经过检查。',
				'你的应用不需要改动。它可以从 X-Auth-* 请求头中读取用户是谁。',
				'Connect 步骤会给出 Caddy、Traefik 或 nginx 的配置，可以直接粘贴。',
				'每个路径都可以开放给选定用户组的成员、项目中的所有人、任何人，或者不开放给任何人，还可以添加条件：网络、时间段、属性、近期登录。',
				'不需要开启任何开关，所有方案都可以使用。'
			]
		},
		mcpproxy: {
			title: '无需授权代码即可保护 MCP 服务器',
			sentence:
				'把你的 MCP 服务器放在你的代理后面。对于每个请求，代理都会请 FoxAuth 检查令牌以及该工具需要的权限（scope），所以服务器本身不需要任何授权代码。',
			protocol:
				'Forward auth · MCP Authorization · OAuth 2.1 · Protected Resource Metadata (RFC 9728)',
			problemCaption: '在你写好授权代码之前，MCP 服务器谁都能访问。',
			fixCaption: '你的代理检查每个令牌和每个工具。',
			lanes: {
				person: '用户',
				agent: 'AI 智能体',
				proxy: '你的代理',
				mcp: '你的 MCP 服务器',
				fox: 'FoxAuth'
			},
			steps: [
				{
					label: '调用工具',
					text: '智能体调用你的 MCP 服务器。请求先到达你的代理。'
				},
				{
					label: '询问项目',
					text: '在 MCP 服务器看到请求之前，你的代理先请项目检查这个请求。'
				},
				{
					label: '401：到 FoxAuth 登录',
					text: '现在还没有令牌。项目回答 401 并指明自己，你的代理把这个回答转给智能体。'
				},
				{
					label: '登录并允许',
					text: '用户登录，并看到是哪个智能体在请求访问。'
				},
				{
					label: '用于你的服务器的令牌',
					text: '项目签发一个只对你的 MCP 服务器有效的令牌。'
				},
				{
					label: '带着令牌调用',
					text: '智能体带着令牌再次调用这个工具。'
				},
				{
					label: '可以，允许这个工具',
					text: '项目检查令牌以及这个工具需要的权限，然后回答“可以”。'
				},
				{
					label: '带上 X-Auth-* 请求头',
					text: '你的代理把请求转给 MCP 服务器，并在 X-Auth-* 请求头中说明调用者是谁、拥有哪些权限。'
				}
			],
			sees: [
				'登录页面，然后是授权同意页面',
				'页面写出了智能体和你的 MCP 服务器',
				'用户选择允许或拒绝'
			],
			goodToKnow: [
				'声明 API 时，在“Who checks tokens?”处选择“Your proxy”。这个 API 的 Connect 会给出 Caddy、Traefik 或 nginx 的配置，可以直接粘贴。',
				'API 那一行的 Access… 用来设置每个工具需要哪些权限，以及谁可以调用这个 API：某些用户组、某个属性、某个网络、某些时间段。缺少权限的客户端会被准确告知需要申请哪些权限。',
				'智能体要查找的描述文档（protected resource metadata）由项目自己发布，所以你的 MCP 服务器不需要为登录提供任何东西。',
				'被撤销的令牌在代理处仍然有效，直到它过期，除非这个 API 签发的是不透明（opaque）令牌。请把令牌有效期设得短一些。',
				'绑定到密钥的令牌（DPoP 或证书）会被代理拒绝，因为代理无法检查这个密钥。',
				'确保只能通过你的代理访问 MCP 服务器。没有条件时，任何能登录这个项目的人都能获得它的令牌。所有方案都可以使用。'
			]
		},
		proxynetwork: {
			title: '只允许从办公网络访问',
			sentence:
				'为代理后应用的某个路径添加条件：只允许来自您列出的地址。来自其他地方的人在登录之前就会被拒绝。',
			protocol: 'Forward auth · X-Forwarded-For',
			problemCaption: '被盗的密码在任何地方都能用。',
			fixCaption: '只有您的网络能进入。',
			lanes: {
				browser: '浏览器',
				proxy: '您的代理',
				proxied: '您的应用',
				fox: 'FoxAuth'
			},
			steps: [
				{
					label: '打开应用',
					text: '某人在咖啡馆打开您的应用。请求先到达您的代理。'
				},
				{
					label: '询问并附上地址',
					text: '您的代理询问项目，并附上它看到的地址和项目的代理密钥。'
				},
				{
					label: '不是这个网络',
					text: '该地址不在您的列表中，因此项目在登录之前就拒绝。'
				},
				{
					label: '在办公室打开',
					text: '在办公室，同样的请求来自您列出的地址。'
				},
				{
					label: '是的，这是 Anna',
					text: '项目检查地址和其余规则，并回答“是”。'
				},
				{
					label: '带 X-Auth-* 标头',
					text: '您的代理把请求转给您的应用。'
				}
			],
			sees: [
				'从其他地方：一个说明无法从此网络打开应用的页面',
				'从办公室：应用，和以前一样'
			],
			goodToKnow: [
				'您的代理必须传递它看到的地址，并出示项目的代理密钥。应用的 Connect 页面会给出要添加的配置行，以及一个检查浏览器无法自选地址的测试。',
				'在收到带密钥和公网地址的检查之前，无法保存网络条件，因此一次保存不会把所有人挡在外面。',
				'条件沿路径向下累加：/ 上的条件适用于其下的每个路径。',
				'VPN 或住宅代理仍然可以绕过列表。它能拖慢攻击者，但无法阻止。',
				'FoxAuth 控制台永远不受这些条件限制。所有套餐均可使用。'
			]
		},
		proxyfresh: {
			title: '在管理页面前要求重新登录',
			sentence:
				'为 /admin 等路径添加条件：当登录时间超过您允许的范围时，要求重新登录。昨天的登录将无法再打开它。',
			protocol: 'Forward auth · OpenID Connect max_age',
			problemCaption: '昨天的登录也能打开管理页面。',
			fixCaption: '管理页面要求近期登录。',
			lanes: {
				browser: '浏览器',
				proxy: '您的代理',
				proxied: '您的应用',
				fox: 'FoxAuth'
			},
			steps: [
				{
					label: '打开 /admin',
					text: '此人今天早上登录过，现在打开 /admin。'
				},
				{
					label: '询问项目',
					text: '您的代理就该请求询问项目。'
				},
				{
					label: '重新登录',
					text: '登录时间超过 /admin 允许的范围，因此项目将浏览器转去重新登录，并说明原因。'
				},
				{
					label: '登录',
					text: '此人重新登录；如果使用身份验证器应用，项目还会要求输入验证码。'
				},
				{
					label: '是的，登录是新的',
					text: '回到 /admin 时登录是近期的，项目回答“是”。'
				},
				{
					label: '带 X-Auth-* 标头',
					text: '您的代理把请求转给管理页面。'
				}
			],
			sees: ['登录页面，并说明应用要求重新登录', '然后是所打开的页面'],
			goodToKnow: [
				'可选择 15 分钟、1 小时、8 小时或 1 天。在后台加载数据的页面（例如仪表板）会停止工作，直到用户重新加载，因此请将其用于管理路径。',
				'如果项目在登录时要求身份验证器应用，重新登录也会要求输入验证码。',
				'通过外部身份提供方登录的人会被要求在那里重新登录；那次登录有多新，由该提供方决定。',
				'所有套餐均可使用。'
			]
		},
		signup: {
			title: '用户自己创建账户，或通过邀请加入',
			sentence:
				'开启注册后，登录页面会出现“立即注册”链接。你也可以在 Users 页面亲自邀请用户。',
			protocol: 'OpenID Connect · email_verified',
			problemCaption: '每个账户都要手工创建。',
			fixCaption: '用户自己注册，或者接受邀请。',
			lanes: { person: '用户', fox: 'FoxAuth', mail: '收件箱' },
			steps: [
				{ label: '创建账户', text: '用户点击“立即注册”，并输入电子邮件地址。' },
				{ label: '带链接的邮件', text: 'FoxAuth 发送一封确认邮件。' },
				{ label: '打开邮件', text: '用户打开这封邮件。' },
				{ label: '确认', text: '用户点击其中的链接。' },
				{
					label: '地址已验证',
					text: '该地址被标记为已验证：你的应用会收到 email_verified = true。'
				}
			],
			sees: [
				'登录页面上的“立即注册”链接',
				'填写电子邮件地址和密码的表单',
				'一封带确认链接的邮件'
			],
			goodToKnow: [
				'发送邮件需要先配置邮件服务器（SMTP）。',
				'只有用户真正确认过地址，它才会被标记为已验证。',
				'如果项目允许，忘记的密码可以通过邮件重置。这时登录页面会显示相应的链接。'
			],
			actionLabel: '打开 Sign-in'
		},
		totp: {
			title: '登录时的第二因素',
			sentence:
				'输入密码后，用户还要输入身份验证器应用中的六位验证码。一个开关就能为整个项目开启它。',
			protocol: 'TOTP (RFC 6238)',
			problemCaption: '偷到密码就能登录。',
			fixCaption: '还需要手机上的验证码。',
			lanes: { person: '用户', fox: 'FoxAuth', totp: '身份验证器' },
			steps: [
				{ label: '密码', text: '用户输入密码。' },
				{ label: '需要验证码', text: 'FoxAuth 要求输入第二因素验证码。' },
				{
					label: '6 位数字',
					text: '身份验证器应用显示一个每 30 秒变化一次的验证码。'
				},
				{ label: '输入验证码', text: '用户输入验证码。' },
				{ label: '已登录', text: '登录完成，你的应用拿到令牌。' }
			],
			sees: [
				'密码页面',
				'然后是一个要求输入六位验证码的页面',
				'首次使用时，会出现一个需要扫描的二维码'
			],
			goodToKnow: [
				'任何身份验证器应用都可以。',
				'如果有人丢了手机，管理员可以在该用户的页面上清除其第二因素。'
			],
			actionLabel: '打开 Sign-in'
		},
		knownguessers: {
			title: '阻止已知地址猜测密码',
			sentence:
				'使用 FoxTrust 的列表，其中是被发现猜测密码的地址。列表中的地址在这里可以输错三次密码，之后它的密码登录会被拒绝。',
			protocol: '签名的 IP 信誉列表（FoxTrust）',
			problemCaption: '一个地址尝试成千上万个密码。',
			fixCaption: '已知的猜测者只有三次机会。',
			lanes: {
				foxtrust: 'FoxTrust',
				guesser: '猜测密码者',
				fox: 'FoxAuth',
				person: '用户'
			},
			steps: [
				{
					label: '签名的列表',
					text: '你的服务器每小时从 FoxTrust 下载被发现猜测密码的地址列表，并验证其签名。'
				},
				{
					label: '猜测密码',
					text: '列表中的一个地址对许多账户尝试密码。它的前三个错误密码照常检查。'
				},
				{
					label: '不是这个网络',
					text: '一小时内失败三次后，项目会拒绝它的下一个密码，并且不检查它。只要该地址继续尝试，就一直如此。'
				},
				{
					label: '正确的密码',
					text: '另一个人使用列表中的地址，例如共享的 Wi-Fi，第一次就输入了自己正确的密码。'
				},
				{ label: '已登录', text: '他和以前一样登录，你的应用拿到令牌。' }
			],
			sees: [
				'来自列表中的地址、输错三次密码之后：“此网络暂时无法使用密码登录”、现在可以怎么做，以及一行要发给你的文字',
				'第一次就输入正确密码：和以前一样登录',
				'页面上的其他登录方式保持不变'
			],
			goodToKnow: [
				'由超级管理员在 Settings → Integrations 的 Attack reporting 下开启该列表。需要先开启攻击报告，因为列表是根据各服务器报告的内容生成的。',
				'每个项目一开始都是 Count only。对任何人都没有变化，Sign-in 标签页显示 7 天的数字。当数字表明安全时，再选择 Refuse password sign-in。',
				'被拒绝的人会看到一行要发给你的文字，其中有他的地址。把这个地址添加到 Never check these networks，他就能立即登录。',
				'FoxTrust 永远不会知道谁在登录。超过 3 小时的列表不会被使用，因此不会有人因它被拒绝。',
				'只影响密码登录。通过身份提供商登录、重置密码和注册都不受影响。所有套餐都提供此功能。'
			],
			actionLabel: '打开 Sign-in'
		},
		domain: {
			title: '在你自己的地址上登录',
			sentence:
				'登录页面位于你项目自己的地址上：一个路径，例如 /yourshop，或者本服务器上的一个子域名，例如 yourshop。超级管理员也可以改为把它放在你自己的域名上，例如 login.yourshop.com，这样在用户看来，它就是你的网站。',
			protocol: '每个项目一个签发者',
			problemCaption: '登录发生在别人的地址上。',
			fixCaption: '登录发生在你自己的地址上。',
			lanes: { person: '用户', domain: '你的地址', fox: 'FoxAuth' },
			steps: [
				{
					label: '打开你的地址',
					text: '用户打开项目的地址：一个路径、一个子域名或你自己的域名。'
				},
				{
					label: '到达 FoxAuth',
					text: '这个地址通向 FoxAuth。你自己的域名需要一条指向它的 DNS 记录。'
				},
				{
					label: '找到项目',
					text: 'FoxAuth 根据地址找到项目。项目有自己的签发者和自己的签名密钥。'
				},
				{ label: '你的登录页面', text: '用户在一个显示你的地址的页面上登录。' }
			],
			sees: ['登录页面，地址栏中显示你的地址'],
			goodToKnow: [
				'一个项目只有三种地址中的一种：路径、子域名或你自己的域名。',
				'项目所属团队的所有者可以更改它的路径或子域名，但前提是项目中还没有任何应用、身份提供商、SCIM 连接或已连接的服务。',
				'在那之后，由超级管理员来更改。你自己的域名始终由超级管理员设置。',
				'你自己的域名需要一条 DNS 记录和一张 https 证书。',
				'更改地址会改变签发者，所以请在你的应用中同步更新。'
			],
			actionLabel: '打开 Settings'
		},
		logout: {
			title: '退出一个应用，同时退出所有应用',
			sentence:
				'当用户退出你的某个应用时，FoxAuth 会结束用户的会话，并通知用户用过的其他每个应用，以便它们也将用户登出。',
			protocol: 'OIDC RP-Initiated Logout · OIDC Back-Channel Logout',
			problemCaption: '退出登录后，其他应用仍然处于登录状态。',
			fixCaption: '一次退出，所有应用都退出。',
			lanes: {
				person: '用户',
				webapp: '你的应用',
				fox: 'FoxAuth',
				apps: '你的其他应用'
			},
			steps: [
				{
					label: '点击“退出登录”',
					text: '用户在你的某个应用中点击“退出登录”。'
				},
				{ label: '结束会话', text: '你的应用把用户转到 FoxAuth 的退出地址。' },
				{ label: '会话已结束', text: 'FoxAuth 结束用户的会话。' },
				{
					label: '登出通知',
					text: 'FoxAuth 以服务器到服务器的方式，向用户用过的其他每个应用发送登出通知。'
				},
				{ label: '已退出', text: '用户来到你的“已退出”页面。' }
			],
			sees: ['你自己的“已退出”页面', '其他应用让用户退出时不显示任何页面'],
			goodToKnow: [
				'每个需要接收通知的应用，都要向 FoxAuth 提供一个登出通知地址。',
				'通知在服务器之间发送，所以即使应用的标签页已经关闭也能生效。',
				'只有超级管理员在服务器设置中开启后台通道登出后，才会发送登出通知。',
				'在结束会话之前，先校验登出令牌的签名、iss、aud 和 events 声明。'
			],
			actionLabel: '打开 Applications'
		},
		branding: {
			title: '看起来像你的产品的登录页面',
			sentence:
				'为你的应用设置徽标和主色，登录页面就会带上它们，并以英文、俄文或简体中文显示。',
			protocol: 'OpenID Connect ui_locales · 徽标 · 主色',
			problemCaption: '登录页面看起来像别人的。',
			fixCaption: '你的徽标、你的颜色、用户的语言。',
			lanes: { person: '用户', webapp: '你的应用', fox: 'FoxAuth' },
			steps: [
				{ label: '点击“登录”', text: '用户在你的应用中点击“登录”。' },
				{
					label: '登录，ui_locales=zh-CN',
					text: '你的应用把用户转去登录，并可以说明它偏好的语言。'
				},
				{
					label: '徽标、颜色、语言',
					text: 'FoxAuth 选用你的颜色、用于授权同意页面的徽标，以及用户的语言。'
				},
				{
					label: '你的外观，用户的语言',
					text: '用户在一个看起来像你的产品的页面上登录。'
				}
			],
			sees: [
				'每个登录页面上都有你的主色',
				'授权同意页面上有你的徽标和名称',
				'用户自己的语言'
			],
			goodToKnow: [
				'徽标是你上传的图片：PNG、JPEG 或 WebP，最大 64 KiB。',
				'它们只对你自己组织的应用显示。设备登录不显示，所有回调地址都是本地地址时也不显示。',
				'FoxAuth 会把颜色调整到最接近的易读色调，浅色和深色模式都会处理。',
				'语言首先取用户自己的选择，其次是你的应用的 ui_locales，最后是浏览器的语言。控制台和管理员邮件始终是英文。'
			],
			actionLabel: '打开 Applications'
		},
		myapps: {
			title: '用户查看并移除能访问其账户的应用',
			sentence:
				'每个项目都有一个账户页面，列出能访问当前登录用户的应用，用户可以移除其中任何一个。',
			protocol: '面向最终用户的授权管理',
			problemCaption: '用户看不到哪些应用能访问自己的账户。',
			fixCaption: '用户能看到每个应用，并能移除任何一个。',
			lanes: { person: '用户', fox: 'FoxAuth' },
			steps: [
				{ label: '打开 /account/apps', text: '用户打开你项目的账户页面。' },
				{ label: '有访问权限的应用', text: 'FoxAuth 列出能访问其账户的应用。' },
				{ label: '移除一个', text: '用户移除一个应用。' },
				{
					label: '访问已结束',
					text: 'FoxAuth 结束该应用的访问权限。应用下次请求时会被拒绝。'
				}
			],
			sees: ['能访问其账户的应用列表', '每个应用都有一个移除按钮'],
			goodToKnow: [
				'不需要开启任何东西。',
				'该页面位于你项目自己的地址下，路径是 /account/apps。',
				'在你的应用的账户设置中放一个指向它的链接。'
			],
			actionLabel: '打开账户页面'
		},
		bound: {
			title: '被盗的令牌毫无用处',
			sentence:
				'使用 DPoP 时，每个令牌都必须配合一个新的证明才能使用。证明由一把从不离开你的应用的密钥签名，所以单独复制走的令牌会被拒绝。',
			protocol: 'DPoP (RFC 9449) · mTLS 证书绑定令牌（RFC 8705）',
			problemCaption: '复制走的令牌谁都能用。',
			fixCaption: '令牌只能配合你的应用的密钥使用。',
			lanes: {
				webapp: '你的应用',
				fox: 'FoxAuth',
				api: '你的 API',
				thief: '持有副本的人'
			},
			steps: [
				{
					label: '令牌 + 密钥证明',
					text: '你的应用申请令牌，并用自己的密钥签名一个证明。'
				},
				{ label: '令牌绑定到密钥', text: 'FoxAuth 把令牌绑定到这把密钥。' },
				{ label: '令牌 + 新证明', text: '每次调用都携带令牌和一个新的证明。' },
				{
					label: '复制的令牌',
					text: '持有令牌副本的人没有密钥，所以你的 API 会拒绝它。'
				}
			],
			sees: ['没有人看到任何界面：这是你的应用和你的 API 之间的事'],
			goodToKnow: [
				'你的 API 在校验令牌的同时校验 DPoP 证明。',
				'客户端证书（mTLS）也能起到同样的作用，但只适用于你自己的服务器。'
			],
			actionLabel: '打开 Applications'
		},
		okta: {
			title: '公司登录',
			sentence:
				'添加公司的身份提供商，可以是任何 OpenID 提供商，也可以是某个组织的 Microsoft 目录。你的应用无需任何改动。',
			protocol: 'OpenID Connect · 联合登录',
			problemCaption: '你的应用保存着公司 IT 无法收回的密码。',
			fixCaption: '员工用公司账户登录。',
			lanes: {
				employee: '员工',
				webapp: '你的应用',
				fox: 'FoxAuth',
				idp: 'Okta 或 Entra ID'
			},
			steps: [
				{ label: '登录', text: '员工点击“登录”。' },
				{ label: '转到登录页', text: '你的应用照常把员工转到 FoxAuth。' },
				{
					label: '转到公司的 Okta',
					text: 'FoxAuth 把员工转到其公司的身份提供商。'
				},
				{ label: '员工身份已确认', text: '公司的身份提供商确认员工的身份。' },
				{ label: '令牌', text: '你的应用拿到普通的令牌。' }
			],
			sees: [
				'登录页面上有一个带公司名称的按钮',
				'然后是公司自己的登录页面，再返回'
			],
			goodToKnow: [
				'你需要向公司的 IT 部门索要：身份提供商的地址、一个 ID 和一个密钥。',
				'它通常和下一项一起出现：公司还希望由自己的目录来创建和移除人员。'
			]
		},
		scim: {
			title: '人员自动加入和离开',
			sentence:
				'有了 SCIM 连接，公司的目录就能在你的项目中创建、修改和停用人员，而你的应用仍然向 FoxAuth 询问谁可以登录。',
			protocol: 'SCIM 2.0 (RFC 7644)',
			problemCaption: '每个人都要手工添加和移除。',
			fixCaption: '公司的目录自动添加和移除人员。',
			lanes: { dir: '公司目录', fox: 'FoxAuth', employee: '员工' },
			steps: [
				{
					label: '入职：创建',
					text: '有人加入公司。目录在 FoxAuth 中创建此人。'
				},
				{ label: '调岗：更新', text: '此人调到另一个部门。目录更新其记录。' },
				{ label: '离职：停用', text: '此人离职。目录停用此人。' },
				{ label: '尝试登录', text: '之后，此人尝试登录你的某个应用。' },
				{
					label: '拒绝',
					text: 'FoxAuth 拒绝登录。你的应用不会收到任何消息：它只是永远拿不到此人的令牌。'
				}
			],
			sees: [
				'公司的 IT 部门在自己的目录中看到这个连接',
				'已离职的人在登录时被拒绝'
			],
			goodToKnow: [
				'你向公司的 IT 部门提供一个 SCIM 地址和一个令牌。它们可以用于 Entra ID 或 Okta。',
				'来自目录的人员在控制台中是只读的，只有本地锁定除外。',
				'它通常和公司登录一起出现，并且能与你已添加的身份提供商配合使用。'
			]
		},
		groups: {
			title: '令牌中的部门和角色',
			sentence:
				'把人员放进项目的用户组，你的应用就会在令牌的 groups 字段中拿到这些用户组，并决定显示什么。',
			protocol: 'OpenID Connect · groups 声明',
			problemCaption: '你的应用不知道用户属于哪个部门。',
			fixCaption: '部门信息随令牌一起到达。',
			lanes: { person: '用户', webapp: '你的应用', fox: 'FoxAuth' },
			steps: [
				{ label: '登录', text: 'Anna 登录你的应用。' },
				{
					label: 'Anna 属于“财务”',
					text: '在项目中，Anna 是“财务”用户组的成员。'
				},
				{ label: 'groups: 财务', text: '你的应用在令牌中拿到她所在的用户组。' },
				{ label: '显示对应的部分', text: '你的应用为 Anna 打开财务板块。' }
			],
			sees: ['没有人看到任何界面：用户组随令牌一起到达'],
			goodToKnow: ['公司的目录也可以通过 SCIM 发送用户组。'],
			actionLabel: '打开 Groups'
		},
		offboard: {
			title: '有人离职：所有地方的访问都已关闭',
			sentence:
				'在 FoxAuth 中停用此人，或者让公司的身份提供商自动将此人从所有地方登出。',
			protocol: 'Okta Universal Logout · OIDC Back-Channel Logout',
			problemCaption: '有人已经离职，访问权限却还开着。',
			fixCaption: '改一处，所有地方的访问都关闭。',
			lanes: {
				itadmin: '公司 IT',
				idp: 'Okta 或 Entra ID',
				fox: 'FoxAuth',
				apps: '你的应用'
			},
			steps: [
				{ label: '停用', text: 'IT 部门在自己那边停用这名员工。' },
				{
					label: '全部退出',
					text: '公司的身份提供商通知 FoxAuth 让此人退出登录。'
				},
				{ label: '会话已结束', text: 'FoxAuth 结束会话并撤销令牌。' },
				{ label: '登出通知', text: '你的应用收到登出通知。' }
			],
			sees: ['此人从每个应用中退出登录，不会看到任何页面'],
			goodToKnow: [
				'你也可以手动操作：打开 Users，选择此人，点击 Deactivate。',
				'只有在你添加了公司的身份提供商，并且超级管理员在服务器设置中开启它发送的信号之后，它才能替你完成这件事。'
			],
			actionLabel: '打开 Users'
		},
		idjag: {
			title: '公司的智能体，无需授权同意页面',
			sentence:
				'公司的身份提供商给智能体一个断言，FoxAuth 用它换出一个令牌，所以访问权限始终由公司掌控。',
			protocol: 'ID-JAG · OAuth 2.0 Token Exchange (RFC 8693) · JWT bearer',
			problemCaption: '没有人在场点击“允许”。',
			fixCaption: '公司为自己的智能体担保。',
			lanes: {
				agent: 'AI 智能体',
				idp: 'Okta 或 Entra ID',
				fox: 'FoxAuth',
				api: '你的 API'
			},
			steps: [
				{
					label: '请求访问',
					text: '智能体向公司的身份提供商请求访问你的应用。'
				},
				{ label: '断言', text: '身份提供商签发一个断言（ID-JAG）。' },
				{ label: '交换断言', text: '智能体把断言提交给 FoxAuth。' },
				{ label: '令牌', text: 'FoxAuth 签发令牌，不显示授权同意页面。' },
				{ label: '开始工作', text: '智能体调用你的 API。' }
			],
			sees: ['没有人看到授权同意页面：公司已经做了决定'],
			goodToKnow: [
				'信任在身份提供商上开启：“Accept assertions”。',
				'这些令牌不附带刷新令牌。',
				'断言永远不会到达管理 MCP 或 SCIM。'
			],
			actionLabel: '打开 Identity providers'
		},
		rar: {
			title: '用户批准一项具体的操作',
			sentence:
				'你的应用请求一项描述详尽的操作，授权同意页面准确显示这项操作，令牌也只携带这项操作。',
			protocol:
				'Rich Authorization Requests (RFC 9396) · authorization_details',
			problemCaption: '一次同意放行的远远超出本意。',
			fixCaption: '用户只批准一项具体的操作。',
			lanes: {
				webapp: '你的应用',
				fox: 'FoxAuth',
				person: '用户',
				api: '你的 API'
			},
			steps: [
				{
					label: '批准：支付 €100',
					text: '你的应用为一笔支付申请令牌，并详细描述这笔支付。'
				},
				{ label: '显示这笔支付', text: 'FoxAuth 向用户显示这笔支付本身。' },
				{ label: '批准', text: '用户批准这笔支付。' },
				{
					label: '用于这笔支付的令牌',
					text: 'FoxAuth 签发一个只携带这笔支付的令牌。'
				},
				{
					label: '支付 €100',
					text: '你的支付 API 从令牌中读取详细信息并执行。'
				}
			],
			sees: [
				'授权同意页面显示这笔支付：金额和账户',
				'用户只批准这笔支付，不批准别的'
			],
			goodToKnow: [
				'每种操作只需在服务器设置中声明一次，同时写明授权同意页面显示的标签。',
				'这些详细信息只会进入发给某一个已声明 API 的令牌。',
				'它适用于登录授权码和刷新令牌，不适用于其他流程。'
			],
			actionLabel: '打开该设置'
		},
		ciba: {
			title: '在手机上批准',
			sentence: '请求送到用户的手机上，发起请求的系统拿到令牌。',
			protocol: 'OpenID Connect CIBA',
			problemCaption: '客户要把密码大声说出来。',
			fixCaption: '客户在自己的手机上批准。',
			lanes: { operator: '呼叫中心系统', fox: 'FoxAuth', client: '客户的手机' },
			steps: [
				{ label: '为 Anna 确认', text: '呼叫中心系统请求 Anna 批准。' },
				{ label: '请求发到手机', text: 'Anna 在手机上收到请求。' },
				{ label: '批准', text: 'Anna 批准。' },
				{ label: '令牌', text: '系统拿到令牌，继续工作。' }
			],
			sees: ['用户的手机上：谁在请求，请求什么', '批准或拒绝'],
			goodToKnow: ['这是整个服务器的设置，由超级管理员开启。'],
			actionLabel: '打开该设置'
		},
		ipsie: {
			title: '最严格的安全规范',
			sentence:
				'IPSIE SL1 规范只需一个开关就能启用。在此之前，就绪检查会先显示哪些地方会改变。',
			protocol: 'IPSIE SL1 · DPoP (RFC 9449) · PKCE',
			problemCaption: '没人说得清哪些规则真正在执行。',
			fixCaption: '先做就绪检查，再打开一个严格开关。',
			lanes: { security: '安全团队', fox: 'FoxAuth' },
			steps: [
				{ label: '就绪检查', text: '你运行就绪检查。' },
				{ label: '会改变什么', text: 'FoxAuth 列出将会停止工作的应用。' },
				{ label: '开启', text: '你开启这个规范。' },
				{ label: '严格规则', text: '这些规则现在适用于每个应用。' }
			],
			sees: ['控制台中的就绪报告，在任何改变发生之前给出'],
			goodToKnow: [
				'先运行就绪检查：它会列出将会停止工作的应用。',
				'每个令牌都通过 DPoP 绑定到应用的密钥，所以被盗的令牌毫无用处。',
				'每次登录都必须使用 PKCE，并且只有预先注册的应用才能登录。',
				'签名使用 PS256、ES256 或 EdDSA。',
				'另一项单独的设置 FAPI behaviours，还会要求应用签名的断言只把本服务器列为受众。',
				'这是整个服务器的设置。'
			],
			actionLabel: '打开该设置'
		},
		teams: {
			title: '团队与审计日志',
			sentence:
				'项目归团队所有。只有成员身份能授予访问权限。每项更改都会写入一份任何人都无法编辑的日志。',
			protocol: '不可篡改的审计日志',
			problemCaption: '所有人共用一个管理员账户。',
			fixCaption: '每个团队只能访问自己的项目。',
			lanes: { team: '团队', project: '项目', audit: '审计日志' },
			steps: [
				{ label: '拥有', text: '支付团队拥有自己的项目。' },
				{ label: '成员操作', text: '只有团队成员能访问项目。' },
				{ label: '每项更改', text: '每项更改都写入日志。' },
				{ label: '无法编辑', text: '任何人都无法修改或删除日志条目。' }
			],
			sees: ['控制台中的日志：谁在什么时间改了什么'],
			goodToKnow: [
				'没有角色：团队成员身份就是访问权限。',
				'日志在菜单的 Audit 下。'
			],
			actionLabel: '打开 Teams'
		},
		adminapps: {
			title: '只给你的管理员用的工具',
			sentence:
				'把这个工具注册为管理员项目中的应用，groups 字段就会写出管理员所在的团队。',
			protocol: 'OpenID Connect · groups 声明',
			problemCaption: '任何人都能打开内部工具。',
			fixCaption: '只有你的管理员能进入。',
			lanes: { admin: '管理员', tool: '内部工具', fox: 'FoxAuth' },
			steps: [
				{ label: '打开工具', text: '管理员打开内部工具。' },
				{ label: '管理员登录', text: '工具把管理员转到管理员登录页面。' },
				{ label: 'groups: 所在团队', text: '工具拿到管理员所在的团队。' },
				{ label: '放行对应的团队', text: '工具只向它信任的团队开放。' }
			],
			sees: ['管理员登录页面，然后回到工具'],
			goodToKnow: [
				'由超级管理员注册，而且只能在控制台中注册。',
				'只用于登录：这类应用拿不到任何 API 的令牌。'
			],
			actionLabel: '打开管理员项目的应用'
		},
		consolesso: {
			title: '你的管理员用公司 SSO 登录控制台',
			sentence:
				'把公司的身份提供商添加到管理员项目，控制台的登录页面就会提供它，同时 FoxAuth 确保控制台永远不会把自己锁住。',
			protocol: 'OpenID Connect · 控制台联合登录',
			problemCaption: '控制台需要一个单独的密码。',
			fixCaption: '管理员用公司的登录方式进入控制台。',
			lanes: { admin: '管理员', fox: 'FoxAuth', idp: 'Okta 或 Entra ID' },
			steps: [
				{
					label: '打开控制台',
					text: '管理员打开控制台，选择公司的身份提供商。'
				},
				{
					label: '转到公司的 Okta',
					text: 'FoxAuth 把管理员转到公司的身份提供商。'
				},
				{ label: '管理员身份已确认', text: '身份提供商确认管理员的身份。' },
				{
					label: '找到管理员',
					text: 'FoxAuth 把此人关联到其已有的管理员账户。'
				},
				{ label: '进入控制台', text: '管理员进入控制台。' }
			],
			sees: [
				'控制台登录页面上有一个公司按钮',
				'然后是公司自己的登录页面，再返回'
			],
			goodToKnow: [
				'只有超级管理员能配置它。',
				'新的身份提供商只放行已经有管理员账户的人。第一次关联时需要输入其密码。',
				'只有在超级管理员仍能通过身份提供商登录时，才能关闭密码登录。'
			],
			actionLabel: '打开管理员项目的身份提供商'
		}
	}
} satisfies GuideTexts;
