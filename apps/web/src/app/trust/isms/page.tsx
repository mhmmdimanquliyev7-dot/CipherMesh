import type { Metadata } from 'next';
import { PageHeader } from '../../../components/ui';
import { ControlCenter } from '../../../isms/control-center';
import { DocumentLink } from '../../../trust/ui';

export const metadata: Metadata = { title: 'ISMS Control Center' };

/** The operational ISMS (ADR-016; PA-06 to PA-08, platform administrators with MFA only). */
export default function IsmsPage() {
  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Information security management system"
        title="ISMS Control Center"
        description={
          <>
            The management process that governs CipherMesh's controls: scope and context, assets, risk assessment and
            treatment, the Statement of Applicability, control verification against evidence, internal audit, corrective
            action, management review and continual improvement. An academic ISO/IEC 27001:2022-aligned ISMS; not
            certified. Manual: <DocumentLink path="docs/security/isms-operations.md">isms-operations.md</DocumentLink>
          </>
        }
      />
      <ControlCenter />
    </div>
  );
}
