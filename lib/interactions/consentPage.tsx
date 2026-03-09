import React from 'react';
import { Button, Card, Typography, Space } from 'antd';

const { Title, Paragraph } = Typography;

interface ConsentPageProps {
	uid: string;
	clientName: string;
	scopes: string[];
}

export const ConsentPage: React.FC<ConsentPageProps> = ({ clientName }) => (
	<Space
		orientation="vertical"
		style={{
			width: '100%',
			height: '100%',
			justifyContent: 'center',
			alignItems: 'center'
		}}
	>
		<Card style={{ maxWidth: 400, width: '100%' }}>
			<Title level={3}>Consent Required</Title>
			<Paragraph>
				<b>{clientName}</b> is requesting access to your account to get email
				and profile information.
			</Paragraph>
			<form method="post">
				<Space style={{ width: '100%', justifyContent: 'flex-end' }}>
					<Button
						htmlType="submit"
						name="action"
						value="cancel"
					>
						Cancel
					</Button>
					<Button
						type="primary"
						htmlType="submit"
						name="action"
						value="allow"
					>
						Allow
					</Button>
				</Space>
			</form>
		</Card>
	</Space>
);
