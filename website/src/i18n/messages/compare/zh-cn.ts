import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '5e08f29ecbef';

export default {
	title: '与 Keycloak、Auth0 等对比',
	description:
		'FoxAuth 与 Keycloak、Auth0、Zitadel、authentik 和 Ory Hydra 在托管、协议、管理和许可上的对比，注明日期和来源。',
	eyebrow: '对比',
	heading: '对照每个产品自己的文档核实。',
	lead: '每篇对比都列出我们查阅过的页面和查阅日期。如果某个产品的文档没有回答某个问题，对应的行会写「not documented」（未记载）。我们不做猜测。',
	shortVersion: {
		eyebrow: '简而言之',
		heading: '哪个服务器合适，由三个问题决定，没有一个是功能数量。',
		questions: [
			{
				question: '数据存放在哪里？',
				answer:
					'根据我们的经验，大多数选择都由这个问题决定。托管服务把你的用户放在它的基础设施上，并按用户向你收费；自托管的 FoxAuth 把用户放在你自己运行的数据库里，不向你收取任何费用；FoxAuth Cloud 把用户放在我们的基础设施上，其免费方案同样不收费。如果监管机构、合同或采购审查要求身份数据留在你自己的环境内，那么答案已经确定，本页其余内容都只是细节。'
			},
			{
				question: '费用随什么增长？',
				answer:
					'托管身份服务按月活跃用户计价，规模小时很便宜，而这种计价方式也正是大多数团队开始寻找替代方案的原因。自托管把这部分成本转移到基础设施上，以及维持服务器健康运行所需的工程时间上。规模大了以后，自托管的账单通常更小，但这笔钱仍然要花。'
			},
			{
				question: '你的团队已经在运行什么？',
				answer:
					'熟悉 JVM 和关系型数据库的团队，不管协议对比表怎么写，走向 Keycloak 的路多半都比走向其他方案的更短。对写 TypeScript 的团队来说，走向 Keycloak 的路反而更长。运维上的熟悉程度胜过功能对比的次数，比对比表显示的要多。'
			}
		],
		candour: rich(
			'FoxAuth 落后的地方，这些页面会直说：它不支持 SAML，也没有支持计划；它的首个稳定版本 ',
			{ code: '1.0.0' },
			' 直到 2026 年 10 月才发布；它也没有多年部署才能积累出的生产环境打磨。它领先的地方，表格里同样会写明：无需更高套餐就能用上银行级安全规范（DPoP、PAR、CIBA、mTLS、RAR 和 JARM），以及 AI 智能体通过与人相同的、经过审计的路径来管理实例。'
		)
	},
	lastChecked: {
		before: '最后核实于 ',
		after: (sources: number) => ` · ${sources} 个来源`
	}
} satisfies typeof english;
