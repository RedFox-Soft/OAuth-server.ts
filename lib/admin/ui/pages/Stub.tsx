import { Result } from 'antd';

export function Stub({ title }: { title: string }) {
	return (
		<Result
			status="info"
			title={title}
			subTitle="Coming soon"
		/>
	);
}
