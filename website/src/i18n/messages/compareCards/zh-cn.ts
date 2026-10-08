export const source = '';

export default {
	auth0: {
		title: 'FoxAuth 与 Auth0 对比',
		description:
			'Auth0 是按月活跃用户计费的托管身份服务。FoxAuth 是由你自己运行的服务器，包含全部协议功能。',
		bottomLine:
			'如果你想本周就用上身份即服务，还需要社交登录连接和一份可以交给审查方的 FAPI 认证，Auth0 是更好的选择。如果数据必须存放在你自己的数据库里、按用户计费成了问题，或者你需要银行级安全规范而不想购买 Enterprise 附加组件，FoxAuth 是更好的选择。'
	},
	authentik: {
		title: 'FoxAuth 与 authentik 对比',
		description:
			'authentik 是自托管的身份提供商，除 OIDC 外还支持 SAML、LDAP 和 RADIUS。FoxAuth 只做 OAuth 2.1，并内置银行级安全规范。',
		bottomLine:
			'如果你要替换的是一套除 OIDC 外还使用 SAML、LDAP 或 RADIUS 的 SSO 体系，选 authentik。如果应用都是你自己的，你需要的是一个带银行级安全规范的 OAuth 2.1 授权服务器，并且不想购买企业版套餐，选 FoxAuth。'
	},
	keycloak: {
		title: 'FoxAuth 与 Keycloak 对比',
		description:
			'两者都是由你自行运行的服务器，区别在于运行时、存储、覆盖范围，以及默认开启了多少协议功能。',
		bottomLine:
			'如果你现在就需要 SAML、LDAP 联合身份或经过认证的 FAPI，选 Keycloak。如果团队写 TypeScript、希望默认就是 OAuth 2.1 的行为，或者希望 AI 智能体沿着与人相同的审计路径来管理服务器，FoxAuth 更合适。'
	},
	'ory-hydra': {
		title: 'FoxAuth 与 Ory Hydra 对比',
		description:
			'Ory Hydra 是一个 OAuth 2.0 与 OpenID Connect 服务器，登录交给你自己编写的应用处理。FoxAuth 自带登录、授权同意和管理界面。',
		bottomLine:
			'如果你已经有一套身份系统，想在它前面放一个经过加固、采用 Apache 许可的 OAuth 服务器，选 Ory Hydra。如果你不想在签发第一个令牌之前先开发一个登录和授权同意应用，选 FoxAuth。'
	},
	zitadel: {
		title: 'FoxAuth 与 Zitadel 对比',
		description:
			'Zitadel 是一个支持 SAML 并提供托管云的多租户身份平台。FoxAuth 是一个更精简的 OAuth 2.1 服务器，内置银行级安全规范。',
		bottomLine:
			'如果你需要 SAML，或者需要背后有企业合同支撑的托管云，选 Zitadel。如果你想要默认的 OAuth 2.1 行为、无需更高套餐即可使用的银行级安全规范，以及 AGPL 以外的许可证，选 FoxAuth。'
	}
} satisfies Record<
	string,
	{ title: string; description: string; bottomLine: string }
>;
