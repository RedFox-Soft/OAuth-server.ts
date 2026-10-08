import type english from './en.ts';

export const source = '53f73ced2330';

export default {
	title: '功能',
	description:
		'全部授权类型、规范与控制：带 PKCE 的 OAuth 2.1、DPoP、PAR、FAPI、CIBA 与 mTLS，可审计的控制台，以及 MCP 服务器授权。',
	hero: {
		eyebrow: '功能',
		heading: '功能一应俱全，大部分默认关闭。',
		lead: 'FoxAuth 只发布一个服务器，不分功能版本。带 PKCE 的授权码流程和 OpenID Connect 从首次启动起就可用，其余大多数功能都在一个具名开关之后等待启用。实际上，你的攻击面就是你真正要求开启的那些功能。每张卡片都会注明该功能是首次启动即开启，还是等待其开关。',
		flags:
			'下面每个开关都链接到设置参考中的对应条目；该参考由代码生成，写明了默认值和后果。',
		getStarted: '快速开始',
		settingsReference: '设置参考'
	},
	groups: {
		protocol: {
			heading: '协议',
			title: 'OAuth 2.1 客户端能请求的每一种授权类型。',
			blurb:
				'授权类型与端点。带 PKCE 的授权码流程和 OpenID Connect 始终开启；其余大多数需要打开开关。',
			items: {
				pkce: {
					title: '带 PKCE 的授权码流程',
					body: '按照 OAuth 2.1 的要求，每个客户端都必须使用 PKCE，无论是公开客户端还是机密客户端。重定向 URI 精确匹配。'
				},
				oidc: {
					title: 'OpenID Connect Core 1.0',
					body: 'ID 令牌、UserInfo 端点和发现机制，支持标准声明集和成对主体标识符。'
				},
				issuerIdentification: {
					title: '颁发者标识',
					body: '每个授权响应都携带 iss，客户端不会被诱骗接受另一个颁发者的授权码。'
				},
				resourceIndicators: {
					title: '资源指示符',
					body: '用 resource 参数限定令牌的受众，并在资源服务器端校验。默认开启。'
				},
				clientCredentials: {
					title: '客户端凭据授权',
					body: '机器对机器的令牌，不涉及最终用户，scope 按客户端限定。'
				},
				refreshToken: {
					title: '刷新令牌授权',
					body: '长期会话，支持轮换和重用检测。一旦重放令牌，整个授权都会被撤销。默认开启：只要 offline_access 是受支持的 scope 就会提供。'
				},
				deviceFlow: {
					title: '设备授权',
					body: '在电视或命令行工具上登录：到另一台设备上输入用户码即可。'
				},
				ciba: {
					title: 'CIBA',
					body: '客户端发起的后台通道认证：客户端发起请求，用户在带外完成批准。'
				},
				par: {
					title: '推送授权请求',
					body: '客户端先把请求提交给服务器，浏览器中只传递一个 request_uri。'
				},
				requestObjects: {
					title: '请求对象',
					body: '签名的 request 和 request_uri 参数，让授权请求本身受到完整性保护。'
				},
				jarm: {
					title: 'JARM',
					body: '以 JWT 保护的授权响应，经过签名，并可选加密。'
				},
				rar: {
					title: '富授权请求',
					body: '用细粒度的 authorization_details 代替 scope 字符串，适用于支付等场景。'
				},
				introspection: {
					title: '令牌内省',
					body: '资源服务器向颁发者询问某个令牌是否仍然有效，以及它携带了什么。'
				},
				jwtIntrospection: {
					title: 'JWT 格式的内省响应',
					body: '签名的内省响应，适合需要证明自己得到了什么答复的资源服务器。'
				},
				revocation: {
					title: '令牌撤销',
					body: '客户端撤销不再需要的访问令牌或刷新令牌。'
				},
				jwtUserinfo: {
					title: '签名的 UserInfo 响应',
					body: '以签名的 JWT 而非普通 JSON 返回 UserInfo。'
				},
				claimsParameter: {
					title: 'claims 参数',
					body: '按请求选择声明，包括必需声明（essential claims）和 acr 请求。'
				},
				rpInitiatedLogout: {
					title: 'RP 发起的登出',
					body: '由客户端结束会话，并带有确认步骤，单凭一个链接无法悄悄让用户登出。默认开启。'
				},
				backchannelLogout: {
					title: '后台通道登出',
					body: '会话结束时，以服务器到服务器的方式通知该会话的每个客户端。'
				}
			}
		},
		security: {
			heading: '安全',
			title: '发送方约束，以及默认已开启的防护。',
			blurb:
				'银行级安全规范是开关，不是单独的版本。列表中的其余各项从首次启动起就已开启。',
			items: {
				dpop: {
					title: 'DPoP',
					body: '发送方约束的访问令牌和刷新令牌，支持服务器 nonce，因此仅仅盗得令牌并不够用。'
				},
				mtls: {
					title: 'mTLS 客户端认证',
					body: '用客户端证书进行认证，并签发与证书绑定的访问令牌。'
				},
				fapi: {
					title: 'FAPI 规范行为',
					body: 'Financial-grade API 规范要求的更严格检查，一个开关即可启用。'
				},
				encryption: {
					title: '令牌与响应加密',
					body: '使用客户端注册的密钥加密 ID 令牌、UserInfo 和 JARM 响应。'
				},
				totp: {
					title: 'TOTP 第二因素',
					body: '按用户桶启用的基于时间的一次性密码，也可以强制用于管理控制台。'
				},
				pairwise: {
					title: '成对主体标识符',
					body: '每个扇区（sector）使用不同的 sub，盐值取自数据库，两个依赖方无法关联同一个用户。'
				},
				bruteForce: {
					title: '登录暴力破解节流',
					body: '按身份持久化失败计数，锁定时间逐级递增。因节流而被拒绝，看上去与密码错误完全一样。'
				},
				rateLimit: {
					title: '按来源限流',
					body: '按路由类别分级，默认开启，可配置可信代理的跳数。'
				},
				cors: {
					title: '由数据决定的 CORS',
					body: '只有当拥有调用方客户端的项目列出某个来源时，该来源才可读取。没有任何通配符设置能把它打开。'
				},
				headers: {
					title: '安全响应头',
					body: '每个响应都带有 HSTS、Permissions-Policy、防框架嵌入和内容类型方面的保护。'
				},
				scopes: {
					title: '基于 scope 的访问控制',
					body: '按客户端强制执行 scope，在授权端点检查一次，在令牌端点再检查一次。'
				}
			}
		},
		administration: {
			heading: '管理',
			title: '一套管理 API，三个入口。',
			blurb:
				'控制台、HTTP API 和 MCP 工具都分发到同一组路由，因此各项检查和审计写入不会彼此脱节。',
			items: {
				console: {
					title: '管理控制台',
					body: '项目、OAuth 客户端、管理员、用户桶、最终用户、上游身份提供商、设置、SMTP 和签名密钥。'
				},
				audit: {
					title: '只追加的审计日志',
					body: '每个改变状态的管理操作都会记录操作者、操作、目标和时间。记录在变更之前写入，且存储层没有任何更新或删除的途径。'
				},
				mcp: {
					title: '通过 MCP 进行管理',
					body: (toolCount: number) =>
						`${toolCount} 个工具以 OAuth 2.1 受保护资源的形式在 POST /mcp 上提供给 AI 智能体，高影响操作需要两次调用确认。`
				},
				mcpAuthorization: {
					title: '为你自己的 MCP 服务器提供授权',
					body: '把第三方 MCP 服务器声明为某个项目的受保护资源，本服务器就会签发受众恰好是该资源的令牌，这里无需改代码，也无需重启。在拥有独立地址的桶中，声明不需要资源方提供任何东西——它可以是内部服务、运行在 localhost 上，甚至尚未部署——其他租户也可以声明同一个 URL，而不会影响你的声明。令牌默认是自包含的，资源方用所属桶公开的密钥即可验证，无需持有自己的凭据。'
				},
				clientIdMetadataDocument: {
					title: '客户端身份文档',
					body: '值为 HTTPS URL 的 client_id，指向一份描述该客户端的 JSON 文档；按需获取并校验，从不存储。对于事先没有任何关系的客户端，MCP 授权规范首先列出的就是这种机制。'
				},
				registration: {
					title: '动态客户端注册',
					body: '客户端可以自行注册，但须遵守注册策略。MCP 规范已弃用这种方式，转而推荐客户端身份文档。'
				},
				registrationManagement: {
					title: '注册管理',
					body: '使用注册访问令牌读取、更新和删除注册信息。'
				},
				databaseClients: {
					title: '存储在数据库中的客户端',
					body: '客户端保存在服务器自己的存储中，可以通过控制台、API、动态注册或初始化脚本创建。没有静态客户端文件。'
				},
				groupOwnership: {
					title: '组所有权',
					body: '项目和用户桶归某个组所有。除了成员身份，没有任何东西能授予访问权限，而且每个请求都会重新解析一次。'
				},
				bucketAddress: {
					title: '按路径或主机名寻址的桶',
					body: '每个用户桶都是独立的颁发者，有自己的元数据和签名密钥，可以通过服务器下的某个路径或独立的主机名访问——二者选其一，不能同时使用。使用主机名时，浏览器可以按来源隔离该桶的登录 cookie，元数据也只发布在一个位置而不是两个；代价是你需要提供一条 DNS 记录和一张证书。更改地址是一项单独的操作：在破坏任何客户端之前，它会先告诉你哪些客户端会受影响。'
				},
				selfService: {
					title: '最终用户自助服务',
					body: '按桶提供邮箱验证和密码重置，均带有尝试次数上限、冷却时间和一次性链接。'
				},
				federation: {
					title: '使用 Google、Microsoft、Apple 或 GitHub 登录',
					body: '按名称连接其中一个，控制台会告诉你需要在提供商那边做什么，以及要登记的确切回调地址；你只需填入对方签发的值。其他任何 OIDC 提供商都可以手动配置。按用户桶设置，因此每个租户使用自己的应用。'
				},
				signingKeys: {
					title: '签名密钥管理',
					body: '每个拥有独立地址的桶都用自己的密钥签名，并发布在自己的 jwks_uri 上，因此一个租户的令牌永远无法在另一个租户的资源服务器上通过验证。密钥由拥有该桶的组负责轮换——新密钥先发布、后签名，退役的密钥会一直保持发布，直到它签发的令牌过期——而实例级密钥集仍由超级管理员掌管。'
				}
			}
		},
		extensibility: {
			heading: '可扩展性',
			title: '无需 fork 即可改变行为。',
			blurb: '具名扩展点加上统一的适配器接口，你的改动应当能平稳度过升级。',
			items: {
				overrideSeams: {
					title: '31 个覆盖扩展点',
					body: '账户查找、交互策略、刷新令牌轮换、资源解析、成对标识符、RAR 处理等，都可以在调用时替换。'
				},
				storage: {
					title: '可插拔存储',
					body: (backends: string) =>
						`每个持久化模型都经过同一个适配器接口。随附的实现有：${backends}；由一个连接字符串决定使用哪一个。`
				},
				mountable: {
					title: '可挂载的 Elysia 应用',
					body: '导入这个应用，挂载到你自己的 Bun 服务中。没有初始化步骤——导入即启动。'
				},
				loginUi: {
					title: '内置登录与授权同意界面',
					body: '基于 React 和 Ant Design 的页面，可以自定义主题，也可以通过交互策略整体替换。'
				}
			}
		},
		operations: {
			heading: '运维',
			title: '出问题时你需要的东西。',
			blurb: '发布它，观察它，查清某个请求为什么失败。',
			items: {
				containerImage: {
					title: '已发布的容器镜像',
					body: 'ghcr.io/redfox-soft/oauth-server-ts，每个版本都有对应标签，另有 latest；附带一个会预配数据库结构的 Compose 文件。'
				},
				errorStore: {
					title: '服务器错误存储',
					body: '内部故障会被记录下来，可以在控制台中查看。常规的客户端拒绝属于正确行为，从不出现在这里。'
				},
				sentry: {
					title: '可选的 Sentry 上报',
					body: '上报完全不在请求路径上：故障只有在被判定为缺陷之后才会到达上报环节，因此响应不受任何影响。'
				},
				settings: {
					title: '看得懂的设置',
					body: '每项服务器级设置都写明了类型、默认值和后果，并可在控制台中编辑。'
				},
				machineReadable: {
					title: '机器可读的参考文档',
					body: '端点、设置、管理 API、MCP 工具和环境变量的参考文档，都直接由代码本身生成。'
				}
			}
		}
	},
	inMemoryBackend: '内存',
	screenshots: {
		auditTrail: {
			alt: '管理审计日志，列出每次更改的操作者、操作、目标和时间戳。',
			caption:
				'审计日志。记录在变更之前写入，存储层不提供更新或删除，因此记录写入后无法再被篡改。'
		},
		settings: {
			alt: '管理控制台的设置面板，显示各授权类型的开关及其当前值。',
			caption:
				'设置按领域分面板。这里的开关与参考文档中记录的是同一个键；更改在保存之前会作为一份完整配置整体校验。'
		}
	},
	next: {
		eyebrow: '下一步',
		heading: '和你现在用的方案比一比。',
		lead: '我们针对团队通常会拿来权衡的那些服务器，维护着一份基于事实、注明日期的对比。',
		allComparisons: '全部对比',
		pricing: '定价'
	}
} satisfies typeof english;
