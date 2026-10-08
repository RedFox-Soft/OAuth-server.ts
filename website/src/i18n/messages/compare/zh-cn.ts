import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '3a1df3dfd09a';

export default {
	title: '对比',
	description:
		'FoxAuth 与 Keycloak、Auth0 在托管方式、协议覆盖、管理和许可上的对比，注明日期，依据它们自己的文档。',
	eyebrow: '对比',
	heading: '对照它们自己的文档核实。',
	lead: '每篇对比都列出我们查阅过的页面和查阅日期。如果某个产品的文档没有回答某个问题，对应的行会写「not documented」（未记载），而不是去猜。',
	shortVersion: {
		eyebrow: '简而言之',
		heading: '决定选择的是三个问题，没有一个是功能数量。',
		questions: [
			{
				question: '数据存放在哪里？',
				answer:
					'根据我们的经验，大多数选择都由这个问题决定。托管服务把你的用户放在它的基础设施上，并按用户向你收费；FoxAuth 把用户放在你自己运行的数据库里，不向你收取任何费用。如果监管机构、合同或采购审查要求身份数据留在你自己的环境内，那么答案已经确定，本页其余内容都只是细节。'
			},
			{
				question: '费用随什么增长？',
				answer:
					'托管身份服务按月活跃用户计价，规模小时很便宜，而这也正是大多数团队开始寻找替代方案的原因。自托管把这部分成本转移到基础设施上，以及维持服务器健康运行所需的工程时间上。规模大了以后，这通常是一笔更小的账单，但它确实存在。'
			},
			{
				question: '你的团队已经在运行什么？',
				answer:
					'熟悉 JVM 和关系型数据库的团队，不管协议对比表怎么写，走向 Keycloak 的路多半都比走向其他方案的更短。写 TypeScript 的团队则恰好相反。运维上的熟悉程度胜过功能对比的次数，比任何对比表愿意承认的都要多。'
			}
		],
		candour: rich(
			'FoxAuth 确实落后的地方，这些页面会直说：它不支持 SAML，也没有支持计划；它处于 ',
			{ code: '0.x' },
			' 版本，HTTP 接口在次版本之间仍可能变化；它也没有多年部署才能积累出的生产环境打磨。它领先的地方，表格里同样会写明：无需更高套餐就能用上银行级安全规范，以及 AI 智能体通过与人相同的、经过审计的路径来管理实例。'
		)
	},
	lastChecked: {
		before: '最后核实于 ',
		after: (sources: number) => ` · ${sources} 个来源`
	}
} satisfies typeof english;
