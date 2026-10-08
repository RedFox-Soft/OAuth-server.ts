import { rich } from '../../types.ts';
import type english from './en.ts';

export const source = '26c44358d86b';

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
				{ link: address, href },
				'，告诉我们你的部署形态和你需要的保障。我们会在两个工作日内回复。'
			)
	},
	waitlist: {
		join: '加入候补名单',
		reassurance: '云服务开放时你会收到一封邮件，仅此一封。不附带任何义务。',
		fallback: (address: string, href: string) =>
			rich(
				'请发邮件至 ',
				{ link: address, href },
				' 加入候补名单。云服务开放时你只会收到一封邮件，不附带任何义务。'
			)
	}
} satisfies typeof english;
