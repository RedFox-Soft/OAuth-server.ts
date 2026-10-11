import { useState } from 'react';
import { Alert, Button, Checkbox, Flex, Typography } from 'antd';
import {
	CopyOutlined,
	EyeInvisibleOutlined,
	EyeOutlined
} from '@ant-design/icons';

/*
 * A value the server shows exactly once — a client secret, a provisioning secret, a static token (specs/084).
 *
 * One component so every such value is handled the same way: masked until asked for, copied in one action,
 * said to be shown only now, and not let go of until the operator says it is stored. The surface that shows
 * it holds it in place — a wizard step, a card, the dialog that created it — never a window stacked over
 * another, which the operator can close by reflex and lose the value with it.
 *
 * Masked by default because the console is often on a shared screen; Show is one click for whoever needs to
 * read it out. The polite announcement on Copy is the only feedback a screen reader would otherwise miss.
 */
export function SecretReveal({
	secret,
	noun = 'secret',
	acknowledged,
	onAcknowledged,
	acknowledgement = "I've stored it where it is needed"
}: {
	secret: string;
	/* What the value is, as the sentence names it: "client secret", "static token". */
	noun?: string;
	acknowledged: boolean;
	onAcknowledged: (value: boolean) => void;
	acknowledgement?: string;
}) {
	const [shown, setShown] = useState(false);
	const [announcement, setAnnouncement] = useState('');

	async function copy() {
		try {
			await navigator.clipboard.writeText(secret);
			setAnnouncement(`The ${noun} was copied.`);
		} catch {
			setShown(true);
			setAnnouncement(
				`The ${noun} could not be copied. Select it and copy it by hand.`
			);
		}
	}

	return (
		<Alert
			type="warning"
			showIcon
			title={`This is the only time the ${noun} is shown.`}
			description={
				<Flex
					vertical
					gap={8}
				>
					<Flex
						gap={8}
						align="center"
						wrap
					>
						<Typography.Text
							code
							style={{ wordBreak: 'break-all' }}
							aria-label={shown ? noun : `${noun}, hidden`}
						>
							{shown ? secret : '•'.repeat(Math.min(secret.length, 24))}
						</Typography.Text>
						<Button
							size="small"
							icon={shown ? <EyeInvisibleOutlined /> : <EyeOutlined />}
							onClick={() => setShown((s) => !s)}
						>
							{shown ? 'Hide' : 'Show'}
						</Button>
						<Button
							size="small"
							icon={<CopyOutlined />}
							onClick={() => void copy()}
						>
							Copy
						</Button>
					</Flex>
					<span
						aria-live="polite"
						style={{ minHeight: 0 }}
					>
						{announcement && (
							<Typography.Text type="secondary">{announcement}</Typography.Text>
						)}
					</span>
					<Checkbox
						checked={acknowledged}
						onChange={(e) => onAcknowledged(e.target.checked)}
					>
						{acknowledgement}
					</Checkbox>
				</Flex>
			}
		/>
	);
}
