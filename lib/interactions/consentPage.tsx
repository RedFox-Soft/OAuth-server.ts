import React from 'react';
import { Button, Card, Typography, List, Space } from 'antd';
import { Form } from 'antd';

const { Title, Paragraph } = Typography;

interface ConsentPageProps {
	uid: string;
	clientName: string;
	scopes: string[];
}

export const ConsentPage: React.FC<ConsentPageProps> = ({
	action,
	clientName,
	scopes
}) => (
	<Space
		direction="vertical"
		style={{ width: '100%', alignItems: 'center', marginTop: 48 }}
	>
		<Card style={{ maxWidth: 400, width: '100%' }}>
			<Title level={3}>Consent Required</Title>
			<Paragraph>
				<b>{clientName}</b> is requesting access to your account with the
				following permissions:
			</Paragraph>
			<List
				size="small"
				bordered
				dataSource={scopes}
				renderItem={(scope) => <List.Item>{scope}</List.Item>}
				style={{ marginBottom: 24 }}
			/>
			<Form
				action={action}
				method="post"
				layout="vertical"
			>
				<Space style={{ width: '100%', justifyContent: 'flex-end' }}>
					<Button
						htmlType="submit"
						name="cancel"
						value="1"
					>
						Cancel
					</Button>
					<Button
						type="primary"
						htmlType="submit"
						name="allow"
						value="1"
					>
						Allow
					</Button>
				</Space>
			</Form>
		</Card>
	</Space>
);
