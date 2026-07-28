# This is still in drafting stages and is in no way shape or form ready for a production environment so the product is currently provided as is with no support


# QuickStart

## Create App registration:

- Create a secret for later

### Permissions:

- EntitlementManagement.Read.All
- GroupMember.Read.All
- RoleAssignmentSchedule.Read.Directory
- RoleEligibilitySchedule.Read.Directory
- RoleManagement.Read.Directory

![MSGraph Permissions](docs\img\msgraph_permissions.png)

## Create Diagnostic setting in Entra ID

- Create a log analytics workspace in a subscription where you have contributor access.
- Go to your log analytics workspace where **AuditLogs** is setup to send it's logs to and add the RBAC role **Monitoring Reader** to your application

![RBAC Permissions](docs\img\rbac_permissions.png)

Go to Entra -> Dianostic Settings -> Create
And check AuditLogs and send it to Log Analytics workspace and select the one you created before

![Diagnostic Settings](docs\img\diagnostic_setting.png)

>NOTE: It can take up to 48 hours before logs start populating normally it takes between 15 min and 2 hours but delays can happen

## Run the code:

```powershell
Copy-Item "JustForTesting_example.ps1" -Destination "JustForTesting.ps1"
# Edit your properties
# $tenantId = "tenantId"
# $appId = "appId"
# $secret = "secret" | ConvertTo-SecureString -AsPlainText -Force
# $workspaceId = "workspaceId"

.\JustForTesting.ps1
```

After the script is run you will have a file called "PrivilegedUsersAnalysis.json" which contains all of the data related to which users has which roles when they used it and wheter or not they need to keep the role based on their activities 

![Sample Output](docs\img\sample_output.png)

