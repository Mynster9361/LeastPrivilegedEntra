import { useEffect, useState } from 'react';
import { ReportMetadata } from '../types';

interface Props {
    metadata: ReportMetadata;
    search: string;
    onSearchChange: (value: string) => void;
    onExportCSV: () => void;
    searchInputRef: React.RefObject<HTMLInputElement>;
}

export function Header({ metadata, search, onSearchChange, onExportCSV, searchInputRef }: Props) {
    const [isDark, setIsDark] = useState(() => document.documentElement.classList.contains('dark'));

    useEffect(() => {
        document.documentElement.classList.toggle('dark', isDark);
        localStorage.theme = isDark ? 'dark' : 'light';
    }, [isDark]);

    return (
        <header className="sticky top-0 z-20 border-b border-gray-200 dark:border-gray-800 bg-white/90 dark:bg-gray-950/90 backdrop-blur">
            <div className="max-w-[1600px] mx-auto px-4 py-3 flex flex-wrap items-center gap-3">
                <div className="flex-1 min-w-[240px]">
                    <h1 className="text-lg font-bold leading-tight">{metadata.title}</h1>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                        {metadata.tenantName ? `${metadata.tenantName} - ` : ''}
                        {metadata.tenantId ? `${metadata.tenantId} - ` : ''}
                        Generated {metadata.generatedOn}
                    </p>
                </div>

                <input
                    ref={searchInputRef}
                    type="search"
                    value={search}
                    onChange={(e) => onSearchChange(e.target.value)}
                    placeholder="Search users, roles, UPN... ( / )"
                    className="w-64 max-w-full px-3 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-sky-500"
                />

                <button
                    onClick={onExportCSV}
                    className="px-3 py-1.5 text-sm font-semibold rounded border border-gray-300 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800"
                >
                    Export CSV
                </button>

                <button
                    onClick={() => setIsDark((v) => !v)}
                    aria-label="Toggle dark mode"
                    className="px-3 py-1.5 text-sm font-semibold rounded border border-gray-300 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800"
                >
                    {isDark ? '☀️ Light' : '🌙 Dark'}
                </button>
            </div>
        </header>
    );
}
