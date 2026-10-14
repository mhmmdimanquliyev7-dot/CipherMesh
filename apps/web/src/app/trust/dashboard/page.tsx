import type { Metadata } from 'next';
import { PageHeader } from '../../../components/ui';
import { DashboardView } from '../../../trust/dashboard-view';
import { DocumentLink } from '../../../trust/ui';

export const metadata: Metadata = { title: 'Platform security dashboard' };

/** Platform security dashboard (Phase 14, CM-T061, CM-T062, PA-01). */
export default function DashboardPage() {
  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Monitoring and measurement"
        title="Platform security dashboard"
        description={
          <>
            Facts about the security state of the platform for the platform administrator acting as security officer
            (ISO/IEC 27001:2022 clause 9.1, control 8.16). Every value comes from a documented query and is shown with
            its definition; there is no composite score. Design:{' '}
            <DocumentLink path="docs/architecture/security-dashboard.md">security-dashboard.md</DocumentLink>
          </>
        }
      />
      <DashboardView />
    </div>
  );
}
