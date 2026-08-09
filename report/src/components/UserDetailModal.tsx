import { useEffect, useState } from 'react';
import { AddRoleEvidence, DeniedRole, DeniedRoleEvidence, RoleUsage, SuggestedRole, UserAnalysis } from '../types';
import { formatDate } from '../utils/helpers';
import { AssignmentBadge, StatusBadge } from './Badges';

interface Props {
    user: UserAnalysis;
    onClose: () => void;
}

function RoleRow({ role }: { role: RoleUsage }) {
    const [expanded, setExpanded] = useState(false);
    const hasActivities = role.RelatedActivities.length > 0;

    return (
        <>
            <tr
                onClick={() => hasActivities && setExpanded((v) => !v)}
                className={`border-b border-gray-100 dark:border-gray-900 ${hasActivities ? 'cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-900' : ''}`}
            >
                <td className="py-2 px-3">
                    {hasActivities && <span className="inline-block w-3 text-gray-400">{expanded ? '▾' : '▸'}</span>}
                    {role.RoleName}
                </td>
                <td className="py-2 px-3">
                    <AssignmentBadge type={role.AssignmentType} />
                </td>
                <td className="py-2 px-3 text-gray-500 dark:text-gray-400">{role.ViaGroup ?? '-'}</td>
                <td className="py-2 px-3">
                    <StatusBadge status={role.Status} />
                </td>
                <td className="py-2 px-3">{formatDate(role.LastUsed)}</td>
                <td className="py-2 px-3">{role.DaysSinceLastUse ?? '-'}</td>
                <td className="py-2 px-3">{role.ActivityCount}</td>
            </tr>
            {expanded && hasActivities && (
                <tr>
                    <td colSpan={7} className="bg-gray-50 dark:bg-gray-900/60 px-3 py-2">
                        <table className="w-full text-xs">
                            <thead>
                                <tr className="text-left text-gray-500 dark:text-gray-400">
                                    <th className="py-1 pr-2 font-medium">Activity</th>
                                    <th className="py-1 pr-2 font-medium">Least privileged Graph permission</th>
                                    <th className="py-1 pr-2 font-medium">Used</th>
                                    <th className="py-1 pr-2 font-medium">Last activity</th>
                                    <th className="py-1 pr-2 font-medium">Count</th>
                                    <th className="py-1 pr-2 font-medium">Failures</th>
                                </tr>
                            </thead>
                            <tbody>
                                {role.RelatedActivities.map((activity, idx) => (
                                    <tr key={idx} className="border-t border-gray-200 dark:border-gray-800">
                                        <td className="py-1 pr-2">
                                            {activity.Category} / {activity.DisplayName}
                                        </td>
                                        <td className="py-1 pr-2 font-mono">{activity.LeastPrivilegedMSGraph ?? '-'}</td>
                                        <td className="py-1 pr-2">{activity.Used ? '✓' : '-'}</td>
                                        <td className="py-1 pr-2">{formatDate(activity.LastActivityTime)}</td>
                                        <td className="py-1 pr-2">{activity.ActivityCount}</td>
                                        <td className="py-1 pr-2">{activity.FailureCount}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </td>
                </tr>
            )}
        </>
    );
}

function SuggestionList({ title, items, tone }: { title: string; items: string[]; tone: string }) {
    if (items.length === 0) return null;
    return (
        <div>
            <h3 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-1">{title}</h3>
            <div className="flex flex-wrap gap-1">
                {items.map((item) => (
                    <span key={item} className={`inline-block px-2 py-0.5 text-xs font-semibold rounded ${tone}`}>
                        {item}
                    </span>
                ))}
            </div>
        </div>
    );
}

// Renders the audit-log evidence behind an AddRoles/DeniedAttempts suggestion - the "proof point" a reviewer would
// otherwise have to go dig out of the audit log by hand to confirm the suggestion is legitimate.
function EvidenceRow({ activity }: { activity: AddRoleEvidence | DeniedRoleEvidence }) {
    const isDenied = 'FailureCount' in activity;
    return (
        <li className="text-xs text-gray-600 dark:text-gray-400 py-0.5">
            <span className="font-medium text-gray-800 dark:text-gray-200">
                {activity.Category} / {activity.DisplayName}
            </span>
            {activity.LeastPrivilegedMSGraph && <span className="ml-1 font-mono text-[11px]">({activity.LeastPrivilegedMSGraph})</span>}
            {isDenied ? (
                <span>
                    {' '}
                    - denied {(activity as DeniedRoleEvidence).FailureCount}x, last attempt{' '}
                    {formatDate((activity as DeniedRoleEvidence).LastAttemptTime)}
                </span>
            ) : (
                <span>
                    {' '}
                    - used {(activity as AddRoleEvidence).ActivityCount}x, last{' '}
                    {formatDate((activity as AddRoleEvidence).LastActivityTime)}
                </span>
            )}
        </li>
    );
}

function EvidenceSuggestionList({
    title,
    items,
    tone,
}: {
    title: string;
    items: (SuggestedRole | DeniedRole)[];
    tone: string;
}) {
    const [expandedRole, setExpandedRole] = useState<string | null>(null);
    if (items.length === 0) return null;

    return (
        <div>
            <h3 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-1">{title}</h3>
            <div className="flex flex-col gap-1">
                {items.map((item) => {
                    const isExpanded = expandedRole === item.RoleName;
                    return (
                        <div key={item.RoleName}>
                            <button
                                onClick={() => setExpandedRole(isExpanded ? null : item.RoleName)}
                                className={`w-full flex items-center justify-between gap-2 px-2 py-1 text-xs font-semibold rounded text-left ${tone}`}
                            >
                                <span>{item.RoleName}</span>
                                <span className="opacity-70 whitespace-nowrap">
                                    {isExpanded ? '▾' : '▸'} {item.Activities.length} activit{item.Activities.length === 1 ? 'y' : 'ies'}
                                </span>
                            </button>
                            {isExpanded && (
                                <ul className="mt-1 mb-2 ml-2 pl-2 border-l-2 border-gray-200 dark:border-gray-800">
                                    {item.Activities.map((activity, idx) => (
                                        <EvidenceRow key={idx} activity={activity} />
                                    ))}
                                </ul>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

export function UserDetailModal({ user, onClose }: Props) {
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape') onClose();
        };
        document.addEventListener('keydown', onKey);
        const previousOverflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden';
        return () => {
            document.removeEventListener('keydown', onKey);
            document.body.style.overflow = previousOverflow;
        };
    }, [onClose]);

    const hasSuggestions =
        user.Suggestion.RemoveRoles.length + user.Suggestion.AddRoles.length + user.Suggestion.DeniedAttempts.length > 0;

    return (
        <div
            className="fixed inset-0 z-30 bg-black/50 flex items-start justify-center p-4 overflow-y-auto"
            onClick={onClose}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                className="w-full max-w-4xl mt-8 mb-8 bg-white dark:bg-gray-950 rounded-lg shadow-xl border border-gray-200 dark:border-gray-800"
            >
                <div className="flex items-start justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-800">
                    <div>
                        <h2 className="text-lg font-bold">{user.DisplayName || '(no display name)'}</h2>
                        <p className="text-sm text-gray-500 dark:text-gray-400">{user.UserPrincipalName || user.Id}</p>
                    </div>
                    <button
                        onClick={onClose}
                        aria-label="Close"
                        className="text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 text-xl leading-none"
                    >
                        ×
                    </button>
                </div>

                <div className="px-5 py-4 space-y-4">
                    {hasSuggestions ? (
                        <div className="grid sm:grid-cols-3 gap-3">
                            <SuggestionList
                                title="Suggested to remove"
                                items={user.Suggestion.RemoveRoles}
                                tone="bg-rose-100 dark:bg-rose-900 text-rose-800 dark:text-rose-200"
                            />
                            <EvidenceSuggestionList
                                title="Suggested to add"
                                items={user.Suggestion.AddRoles}
                                tone="bg-amber-100 dark:bg-amber-900 text-amber-800 dark:text-amber-200"
                            />
                            <EvidenceSuggestionList
                                title="Denied attempts"
                                items={user.Suggestion.DeniedAttempts}
                                tone="bg-sky-100 dark:bg-sky-900 text-sky-800 dark:text-sky-200"
                            />
                        </div>
                    ) : (
                        <p className="text-sm text-emerald-700 dark:text-emerald-300">
                            Every held role is either justified by observed activity or can't be evaluated from audit logs.
                        </p>
                    )}

                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-left border-b border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-300">
                                    <th className="py-2 px-3 font-semibold">Role</th>
                                    <th className="py-2 px-3 font-semibold">Assignment</th>
                                    <th className="py-2 px-3 font-semibold">Via group</th>
                                    <th className="py-2 px-3 font-semibold">Status</th>
                                    <th className="py-2 px-3 font-semibold">Last used</th>
                                    <th className="py-2 px-3 font-semibold">Days since</th>
                                    <th className="py-2 px-3 font-semibold">Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                {user.Roles.map((role) => (
                                    <RoleRow key={`${role.RoleName}-${role.AssignmentType}-${role.ViaGroup ?? ''}`} role={role} />
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
}
