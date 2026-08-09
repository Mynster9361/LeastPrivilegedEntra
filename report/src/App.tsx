import { useEffect, useMemo, useRef, useState } from 'react';
import { FilterState, UserAnalysis } from './types';
import sampleData from './sampleData';
import { Header } from './components/Header';
import { SummaryBanner, FiltersPanel } from './components/FiltersPanel';
import { UserTable } from './components/UserTable';
import { UserDetailModal } from './components/UserDetailModal';
import { calculateStats, exportToCSV } from './utils/helpers';

// LPE_USERDATA_START
const appDataJson = '{% block app_data %}{% endblock %}';
// LPE_USERDATA_END
const rawTitle = '{% block title %}{% endblock %}';
const rawTenantId = '{% block tenant_id %}{% endblock %}';
const rawTenantName = '{% block tenant_name %}{% endblock %}';
const rawGeneratedOn = '{% block generated_on %}{% endblock %}';

function resolvePlaceholder(raw: string, fallback: string): string {
    return raw.startsWith('{% block') ? fallback : raw;
}

function parseUserData(): UserAnalysis[] {
    try {
        const parsed = JSON.parse(appDataJson);
        return Array.isArray(parsed) ? parsed : [parsed];
    } catch {
        // Placeholder wasn't replaced (e.g. `npm run dev`) - fall back to sample data.
        return sampleData;
    }
}

export function App() {
    const [userData] = useState<UserAnalysis[]>(() => parseUserData());
    const [filters, setFilters] = useState<FilterState>({ status: 'all', assignmentType: 'all', search: '' });
    const [selectedUser, setSelectedUser] = useState<UserAnalysis | null>(null);
    const searchInputRef = useRef<HTMLInputElement>(null);

    const metadata = useMemo(
        () => ({
            title: resolvePlaceholder(rawTitle, 'Least Privileged Entra Report'),
            tenantId: resolvePlaceholder(rawTenantId, ''),
            tenantName: resolvePlaceholder(rawTenantName, ''),
            generatedOn: resolvePlaceholder(rawGeneratedOn, new Date().toLocaleString()),
        }),
        []
    );

    useEffect(() => {
        document.title = metadata.title;
    }, [metadata.title]);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.key === '/' && document.activeElement !== searchInputRef.current) {
                e.preventDefault();
                searchInputRef.current?.focus();
            }
        };
        document.addEventListener('keydown', onKey);
        return () => document.removeEventListener('keydown', onKey);
    }, []);

    const filteredUsers = useMemo(() => {
        const search = filters.search.trim().toLowerCase();

        return userData.filter((user) => {
            if (filters.status === 'removable' && user.Suggestion.RemoveRoles.length === 0) return false;
            if (filters.status === 'addable' && user.Suggestion.AddRoles.length === 0) return false;
            if (filters.status === 'denied' && user.Suggestion.DeniedAttempts.length === 0) return false;
            if (
                filters.status === 'clean' &&
                user.Suggestion.RemoveRoles.length + user.Suggestion.AddRoles.length + user.Suggestion.DeniedAttempts.length > 0
            ) {
                return false;
            }

            if (filters.assignmentType !== 'all' && !user.Roles.some((r) => r.AssignmentType === filters.assignmentType)) {
                return false;
            }

            if (search) {
                const haystack = [user.DisplayName, user.UserPrincipalName, ...user.Roles.map((r) => r.RoleName)]
                    .join(' ')
                    .toLowerCase();
                if (!haystack.includes(search)) return false;
            }

            return true;
        });
    }, [userData, filters]);

    const stats = useMemo(() => calculateStats(userData), [userData]);

    return (
        <div className="min-h-screen">
            <Header
                metadata={metadata}
                search={filters.search}
                onSearchChange={(search) => setFilters((f) => ({ ...f, search }))}
                onExportCSV={() => exportToCSV(filteredUsers)}
                searchInputRef={searchInputRef}
            />
            <SummaryBanner stats={stats} />
            <FiltersPanel filters={filters} onChange={setFilters} />
            <UserTable users={filteredUsers} onSelect={setSelectedUser} />
            {selectedUser && <UserDetailModal user={selectedUser} onClose={() => setSelectedUser(null)} />}
        </div>
    );
}
