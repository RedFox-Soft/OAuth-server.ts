import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = 'fd46e1b6bd8d';

export default {
	workEmail: '工作邮箱',
	emailPlaceholder: 'you@company.com',
	contact: {
		need: '你需要什么？',
		needPlaceholder: '你的部署形态、时间安排，以及你需要的保障。',
		send: '发送',
		reassurance: '会有真人回复，通常在两个工作日内。',
		fallback: (address: string, href: string) =>
			rich(
				'请发邮件至 ',
				{ label: address, href },
				'，告诉我们你的部署形态和你需要的保障。我们通常会在两个工作日内回复。'
			)
	},
	enterprise: {
		name: '你的名字',
		company: '公司',
		users: '会有多少人登录',
		usersPlaceholder: '每月约 5,000 人',
		hosting: '服务器在哪里运行？',
		hostingOptions: {
			shared: 'FoxAuth Enterprise Cloud，仅供企业客户共享，提供 SLA',
			ours: '由 FoxAuth 运行、只为我们服务的独立实例',
			yours: '在我们自己的基础设施上，由你们提供支持',
			unsure: '还不确定'
		},
		message: '你需要什么？',
		messagePlaceholder: '你的项目、时间安排，以及为什么需要独立实例。',
		send: '申请邀请',
		reassurance: '会有真人回复，通常在两个工作日内。',
		sent: '谢谢。你的申请已发出，会有真人回复，通常在两个工作日内。'
	}
} satisfies typeof english;
