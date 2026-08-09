import { RoleStatus, SummaryStats, UserAnalysis } from '../types';

export function calculateStats(users: UserAnalysis[]): SummaryStats {
    let roleCount = 0;
    let usedRoleCount = 0;
    let removableRoleCount = 0;
    let usersWithAddSuggestions = 0;
    let usersWithDeniedAttempts = 0;
    let cleanUserCount = 0;

    for (const user of users) {
        roleCount += user.Roles.length;
        usedRoleCount += user.Roles.filter((r) => r.Status === 'Used').length;
        removableRoleCount += user.Suggestion.RemoveRoles.length;
        if (user.Suggestion.AddRoles.length > 0) usersWithAddSuggestions += 1;
        if (user.Suggestion.DeniedAttempts.length > 0) usersWithDeniedAttempts += 1;
        if (
            user.Suggestion.RemoveRoles.length === 0 &&
            user.Suggestion.AddRoles.length === 0 &&
            user.Suggestion.DeniedAttempts.length === 0
        ) {
            cleanUserCount += 1;
        }
    }

    return {
        userCount: users.length,
        roleCount,
        usedRoleCount,
        removableRoleCount,
        usersWithAddSuggestions,
        usersWithDeniedAttempts,
        cleanUserCount,
    };
}

export function formatDate(value?: string | null): string {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

export function statusBadgeClass(status: RoleStatus): string {
    switch (status) {
        case 'Used':
            return 'bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200';
        case 'NotUsedInWindow':
            return 'bg-rose-100 dark:bg-rose-900 text-rose-800 dark:text-rose-200';
        case 'NoMappedActivity':
        default:
            return 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300';
    }
}

export function assignmentBadgeClass(type: string): string {
    return type === 'Eligible'
        ? 'bg-amber-100 dark:bg-amber-900 text-amber-800 dark:text-amber-200'
        : 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200';
}

function csvEscape(value: unknown): string {
    const str = value === null || value === undefined ? '' : String(value);
    if (/[",\n]/.test(str)) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
}

export function exportToCSV(users: UserAnalysis[], fileName = 'PrivilegedUsersAnalysis.csv') {
    const headers = [
        'DisplayName',
        'UserPrincipalName',
        'RoleName',
        'AssignmentType',
        'ViaGroup',
        'Status',
        'LastUsed',
        'DaysSinceLastUse',
        'ActivityCount',
        'RemoveRoles',
        'AddRoles',
        'DeniedAttempts',
    ];

    const rows: string[] = [headers.join(',')];

    for (const user of users) {
        const removeRoles = user.Suggestion.RemoveRoles.join('; ');
        const addRoles = user.Suggestion.AddRoles.map((r) => r.RoleName).join('; ');
        const deniedAttempts = user.Suggestion.DeniedAttempts.map((r) => r.RoleName).join('; ');

        if (user.Roles.length === 0) {
            rows.push(
                [user.DisplayName, user.UserPrincipalName, '', '', '', '', '', '', '', removeRoles, addRoles, deniedAttempts]
                    .map(csvEscape)
                    .join(',')
            );
            continue;
        }

        for (const role of user.Roles) {
            rows.push(
                [
                    user.DisplayName,
                    user.UserPrincipalName,
                    role.RoleName,
                    role.AssignmentType,
                    role.ViaGroup ?? '',
                    role.Status,
                    role.LastUsed ?? '',
                    role.DaysSinceLastUse ?? '',
                    role.ActivityCount,
                    removeRoles,
                    addRoles,
                    deniedAttempts,
                ]
                    .map(csvEscape)
                    .join(',')
            );
        }
    }

    const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}
