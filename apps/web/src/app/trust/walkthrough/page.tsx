import type { Metadata } from 'next';
import { Alert, PageHeader } from '../../../components/ui';
import { DocumentLink } from '../../../trust/ui';
import { WalkthroughView } from '../../../trust/walkthrough-view';

export const metadata: Metadata = { title: 'Guided walkthrough' };

/** The guided security walkthrough (Phase 14 + Prompt 16.5, CM-T061). */
export default function WalkthroughPage() {
  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Presentation"
        title="Guided security walkthrough"
        description="Three journeys through the real application: Cryptography, Cloud & cloud security, and ISMS & governance. Each step says what to do, what it shows and where the evidence is."
      />
      <Alert kind="info">
        Use synthetic accounts and disposable content only. The walkthrough has no access of its own: every step runs
        with your normal session, vault and role. The full script is in{' '}
        <DocumentLink path="docs/report/live-demo-guide.md">live-demo-guide.md</DocumentLink>.
      </Alert>
      <WalkthroughView />
    </div>
  );
}
