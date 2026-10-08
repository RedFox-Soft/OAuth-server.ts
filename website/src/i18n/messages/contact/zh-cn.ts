import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = 'b20904684c90';

export default {
	title: '联系我们',
	description:
		'联系 FoxAuth 团队：一般咨询发至 hello@foxauth.dev，漏洞报告发至 security@foxauth.dev，缺陷提交到 GitHub。',
	eyebrow: '联系',
	heading: '三个联系方式，其中一个是代码仓库。',
	lead: '按你手头的情况选一个。缺陷提交到问题跟踪器，漏洞发到安全邮箱，其他一切——从部署问题到支持合同——都通过表单联系我们。',
	talk: {
		heading: '与我们交流',
		body: '告诉我们你设想的部署形态，咨询支持合同或顾问服务，或者提出文档没有回答的问题。'
	},
	vulnerability: {
		heading: '报告漏洞',
		body: (address: string, href: string) =>
			rich(
				'请发邮件至 ',
				{ link: address, href },
				'，不要提交到公开的问题跟踪器。安全策略说明了我们接下来会怎么做，以及需要多长时间。'
			),
		policy: '安全策略'
	},
	bug: {
		heading: '报告缺陷',
		body: '提交 issue 时请附上版本号、请求和响应。公开的 issue 往往修得更快，因为其他人可以帮忙确认。',
		issues: 'GitHub issues'
	}
} satisfies typeof english;
