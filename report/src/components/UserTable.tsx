import { useMemo, useState } from 'react';
import {
    ColumnDef,
    flexRender,
    getCoreRowModel,
    getSortedRowModel,
    SortingState,
    useReactTable,
} from '@tanstack/react-table';
import { UserAnalysis } from '../types';
import { CountBadge } from './Badges';

interface Props {
    users: UserAnalysis[];
    onSelect: (user: UserAnalysis) => void;
}

export function UserTable({ users, onSelect }: Props) {
    const [sorting, setSorting] = useState<SortingState>([{ id: 'DisplayName', desc: false }]);

    const columns = useMemo<ColumnDef<UserAnalysis>[]>(
        () => [
            {
                id: 'DisplayName',
                header: 'User',
                accessorFn: (row) => row.DisplayName || row.UserPrincipalName || row.Id,
                cell: ({ row }) => (
                    <div>
                        <div className="font-semibold">{row.original.DisplayName || '(no display name)'}</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">{row.original.UserPrincipalName || row.original.Id}</div>
                    </div>
                ),
            },
            {
                id: 'RoleCount',
                header: 'Roles',
                accessorFn: (row) => row.Roles.length,
                cell: ({ getValue }) => <span>{getValue<number>()}</span>,
            },
            {
                id: 'UsedCount',
                header: 'In use',
                accessorFn: (row) => row.Roles.filter((r) => r.Status === 'Used').length,
                cell: ({ getValue }) => <span>{getValue<number>()}</span>,
            },
            {
                id: 'Suggestion',
                header: 'Suggestion',
                enableSorting: false,
                cell: ({ row }) => {
                    const s = row.original.Suggestion;
                    const hasAny = s.RemoveRoles.length + s.AddRoles.length + s.DeniedAttempts.length > 0;
                    return (
                        <div className="flex flex-wrap gap-1">
                            <CountBadge count={s.RemoveRoles.length} label="remove" tone="rose" />
                            <CountBadge count={s.AddRoles.length} label="add" tone="amber" />
                            <CountBadge count={s.DeniedAttempts.length} label="denied" tone="sky" />
                            {!hasAny && (
                                <span className="inline-block px-2 py-0.5 text-xs font-semibold rounded bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200">
                                    justified
                                </span>
                            )}
                        </div>
                    );
                },
            },
        ],
        []
    );

    const table = useReactTable({
        data: users,
        columns,
        state: { sorting },
        onSortingChange: setSorting,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
    });

    return (
        <div className="max-w-[1600px] mx-auto px-4 pb-8 overflow-x-auto">
            <table className="w-full text-sm border-collapse">
                <thead>
                    {table.getHeaderGroups().map((headerGroup) => (
                        <tr key={headerGroup.id} className="text-left border-b border-gray-200 dark:border-gray-800">
                            {headerGroup.headers.map((header) => (
                                <th
                                    key={header.id}
                                    onClick={header.column.getToggleSortingHandler()}
                                    className="py-2 px-3 font-semibold text-gray-600 dark:text-gray-300 select-none cursor-pointer whitespace-nowrap"
                                >
                                    {flexRender(header.column.columnDef.header, header.getContext())}
                                    {{ asc: ' ▲', desc: ' ▼' }[header.column.getIsSorted() as string] ?? ''}
                                </th>
                            ))}
                        </tr>
                    ))}
                </thead>
                <tbody>
                    {table.getRowModel().rows.map((row) => (
                        <tr
                            key={row.id}
                            onClick={() => onSelect(row.original)}
                            className="border-b border-gray-100 dark:border-gray-900 hover:bg-gray-50 dark:hover:bg-gray-900 cursor-pointer"
                        >
                            {row.getVisibleCells().map((cell) => (
                                <td key={cell.id} className="py-2 px-3 align-top">
                                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                </td>
                            ))}
                        </tr>
                    ))}
                    {table.getRowModel().rows.length === 0 && (
                        <tr>
                            <td colSpan={columns.length} className="py-8 text-center text-gray-500 dark:text-gray-400">
                                No users match the current filters.
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>
    );
}
