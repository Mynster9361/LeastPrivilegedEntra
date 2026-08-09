import { FilterState, SummaryStats } from '../types';

interface SummaryBannerProps {
    stats: SummaryStats;
}

export function SummaryBanner({ stats }: SummaryBannerProps) {
    const items: { label: string; value: number; tone: string }[] = [
        { label: 'Privileged users', value: stats.userCount, tone: 'bg-sky-100 dark:bg-sky-900 text-sky-800 dark:text-sky-200' },
        { label: 'Roles held', value: stats.roleCount, tone: 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-200' },
        { label: 'Roles in active use', value: stats.usedRoleCount, tone: 'bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200' },
        { label: 'Roles safe to remove', value: stats.removableRoleCount, tone: 'bg-rose-100 dark:bg-rose-900 text-rose-800 dark:text-rose-200' },
        { label: 'Users with a narrower-role suggestion', value: stats.usersWithAddSuggestions, tone: 'bg-amber-100 dark:bg-amber-900 text-amber-800 dark:text-amber-200' },
        { label: 'Users with denied attempts', value: stats.usersWithDeniedAttempts, tone: 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200' },
    ];

    return (
        <div className="max-w-[1600px] mx-auto px-4 pt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
            {items.map((item) => (
                <div key={item.label} className={`rounded-lg px-3 py-2 ${item.tone}`}>
                    <div className="text-2xl font-bold leading-none">{item.value}</div>
                    <div className="text-xs mt-1 leading-tight">{item.label}</div>
                </div>
            ))}
        </div>
    );
}

interface FiltersPanelProps {
    filters: FilterState;
    onChange: (filters: FilterState) => void;
}

const statusOptions: { value: FilterState['status']; label: string }[] = [
    { value: 'all', label: 'All users' },
    { value: 'removable', label: 'Has removable roles' },
    { value: 'addable', label: 'Has narrower-role suggestion' },
    { value: 'denied', label: 'Has denied attempts' },
    { value: 'clean', label: 'Fully justified' },
];

export function FiltersPanel({ filters, onChange }: FiltersPanelProps) {
    return (
        <div className="max-w-[1600px] mx-auto px-4 py-3 flex flex-wrap items-center gap-2">
            <select
                value={filters.status}
                onChange={(e) => onChange({ ...filters, status: e.target.value as FilterState['status'] })}
                className="px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900"
            >
                {statusOptions.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                        {opt.label}
                    </option>
                ))}
            </select>

            <select
                value={filters.assignmentType}
                onChange={(e) => onChange({ ...filters, assignmentType: e.target.value as FilterState['assignmentType'] })}
                className="px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900"
            >
                <option value="all">Active + Eligible</option>
                <option value="Active">Active only</option>
                <option value="Eligible">Eligible only</option>
            </select>

            {(filters.status !== 'all' || filters.assignmentType !== 'all' || filters.search) && (
                <button
                    onClick={() => onChange({ status: 'all', assignmentType: 'all', search: '' })}
                    className="text-sm text-sky-600 dark:text-sky-400 hover:underline"
                >
                    Clear filters
                </button>
            )}
        </div>
    );
}
