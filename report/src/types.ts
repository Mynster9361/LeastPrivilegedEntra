export type AssignmentType = 'Active' | 'Eligible';

export type RoleStatus = 'Used' | 'NotUsedInWindow' | 'NoMappedActivity';

export interface RelatedActivity {
    Category: string;
    DisplayName: string;
    LeastPrivilegedMSGraph?: string | null;
    Used: boolean;
    LastActivityTime?: string | null;
    ActivityCount: number;
    FailureCount: number;
}

export interface RoleUsage {
    RoleName: string;
    RoleId: string;
    AssignmentType: AssignmentType;
    ViaGroup?: string | null;
    Status: RoleStatus;
    LastUsed?: string | null;
    DaysSinceLastUse?: number | null;
    ActivityCount: number;
    RelatedActivities: RelatedActivity[];
}

export interface AddRoleEvidence {
    Category: string;
    DisplayName: string;
    LeastPrivilegedMSGraph?: string | null;
    ActivityCount: number;
    LastActivityTime?: string | null;
}

export interface DeniedRoleEvidence {
    Category: string;
    DisplayName: string;
    LeastPrivilegedMSGraph?: string | null;
    FailureCount: number;
    LastAttemptTime?: string | null;
}

export interface SuggestedRole {
    RoleName: string;
    Activities: AddRoleEvidence[];
}

export interface DeniedRole {
    RoleName: string;
    Activities: DeniedRoleEvidence[];
}

export interface Suggestion {
    RemoveRoles: string[];
    KeepRoles: string[];
    AddRoles: SuggestedRole[];
    DeniedAttempts: DeniedRole[];
}

export interface UserAnalysis {
    Id: string;
    DisplayName: string;
    UserPrincipalName: string;
    Roles: RoleUsage[];
    Suggestion: Suggestion;
}

export type FilterState = {
    status: 'all' | 'removable' | 'addable' | 'denied' | 'clean';
    assignmentType: 'all' | AssignmentType;
    search: string;
};

export interface ReportMetadata {
    title: string;
    tenantId: string;
    tenantName: string;
    generatedOn: string;
}

export interface SummaryStats {
    userCount: number;
    roleCount: number;
    usedRoleCount: number;
    removableRoleCount: number;
    usersWithAddSuggestions: number;
    usersWithDeniedAttempts: number;
    cleanUserCount: number;
}
