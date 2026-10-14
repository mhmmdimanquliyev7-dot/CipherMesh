import type { Metadata } from 'next';
import { PageHeader } from '../../../components/ui';
import { EvidenceRegister } from '../../../trust/evidence-register';
import { DocumentLink } from '../../../trust/ui';

export const metadata: Metadata = { title: 'Security evidence' };

/** The evidence register (Phase 14 + Prompt 16.5, CM-T061). */
export default function EvidencePage() {
  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Evidence"
        title="Security evidence register"
        description={
          <>
            Every item of the <DocumentLink path="docs/report/evidence-plan.md">evidence plan</DocumentLink>, tagged by
            subject (Cryptography, Cloud security, ISMS, Application security). An item is captured only when a redacted
            file is committed for it or the{' '}
            <DocumentLink path="docs/report/evidence/index.md">evidence index</DocumentLink> records where it is.
            Evidence is synthetic: test accounts and disposable data only.
          </>
        }
      />
      <EvidenceRegister />
    </div>
  );
}
