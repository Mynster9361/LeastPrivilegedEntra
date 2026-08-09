import { AssignmentType, RoleStatus } from '../types';
import { assignmentBadgeClass, statusBadgeClass } from '../utils/helpers';

export function StatusBadge({ status }: { status: RoleStatus }) {
    const label: Record<RoleStatus, string> = {
        Used: 'Used',
        NotUsedInWindow: 'Not used',
        NoMappedActivity: 'No mapped activity',
    };

    return (
        <span className={`inline-block px-2 py-0.5 text-xs font-semibold rounded ${statusBadgeClass(status)}`}>
            {label[status]}
        </span>
    );
}

export function AssignmentBadge({ type }: { type: AssignmentType }) {
    return (
        <span className={`inline-block px-2 py-0.5 text-xs font-semibold rounded ${assignmentBadgeClass(type)}`}>
            {type}
        </span>
    );
}

interface CountBadgeProps {
    count: number;
    label: string;
    tone: 'rose' | 'sky' | 'amber' | 'emerald';
}

const toneClasses: Record<CountBadgeProps['tone'], string> = {
    rose: 'bg-rose-100 dark:bg-rose-900 text-rose-800 dark:text-rose-200',
    sky: 'bg-sky-100 dark:bg-sky-900 text-sky-800 dark:text-sky-200',
    amber: 'bg-amber-100 dark:bg-amber-900 text-amber-800 dark:text-amber-200',
    emerald: 'bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200',
};

export function CountBadge({ count, label, tone }: CountBadgeProps) {
    if (count === 0) return null;
    return (
        <span
            className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-semibold rounded ${toneClasses[tone]}`}
            title={`${count} ${label}`}
        >
            {count} {label}
        </span>
    );
}
