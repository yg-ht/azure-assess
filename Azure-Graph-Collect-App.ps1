#requires -Version 5.1

<#
.SYNOPSIS
Creates a Microsoft Graph app-only collection client for Azure / M365 security assessment.

.DESCRIPTION
This script creates:
  1. A single-tenant Entra ID application registration.
  2. A matching enterprise application / service principal.
  3. Microsoft Graph application permissions from one or more predefined profiles.
  4. A public X.509 certificate credential for app-only authentication.
  5. Optional programmatic admin consent by creating app role assignments.

The script is intended to be run by the tenant administrator.
All permission profiles are selected by default. Use -Profiles only when the assessment requires a deliberately restricted permission set.

Recommended administrator role:
  Privileged Role Administrator

Required delegated Graph scopes for the administrator running this script:
  Application.ReadWrite.All
  AppRoleAssignment.ReadWrite.All

The private key is never uploaded by this script. Only the public certificate is added to the app registration.

.EXAMPLE
.\Azure-Graph-Collect-App.ps1 `
  -TenantId "11111111-2222-3333-4444-555555555555" `
  -CertificatePath ".\collector-public.cer" `
  -Profiles All

#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$DisplayName = "YGHT Azure Assessment Graph App-Only Collector - $(Get-Date -Format 'yyyyMMdd')",

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_)) {
            throw "Certificate file does not exist: $_"
        }

        $extension = [System.IO.Path]::GetExtension($_).ToLowerInvariant()
        if ($extension -in @(".pfx", ".p12")) {
            throw "Do not provide a private key file. Export and provide the public certificate only, for example .cer, .crt, or .pem."
        }

        return $true
    })]
    [string]$CertificatePath,

    [Parameter(Mandatory = $false)]
    [ValidateSet(
        "IdentityBaseline",
        "PIM",
        "M365Audit",
        "EndpointIntune",
        "GlobalSecureAccess",
        "DefenderHunting",
        "All"
    )]
    [string[]]$Profiles = @("All"),

    [Parameter(Mandatory = $false)]
    [string[]]$AdditionalApplicationPermissions = @(),

    [Parameter(Mandatory = $false)]
    [switch]$NoGrant,

    [Parameter(Mandatory = $false)]
    [switch]$AllowDuplicateDisplayName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Module {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Missing PowerShell module: $Name. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    Import-Module $Name -ErrorAction Stop
}

function Escape-ODataString {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.Replace("'", "''")
}

function Get-PublicCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path

    try {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedPath)
    }
    catch {
        throw "Could not load certificate from $resolvedPath. Export a public certificate as .cer, .crt, or .pem and retry. Original error: $($_.Exception.Message)"
    }

    if ($certificate.NotAfter -lt (Get-Date).AddDays(30)) {
        Write-Warning "The certificate expires within 30 days: $($certificate.NotAfter.ToString('u'))"
    }

    if ($certificate.HasPrivateKey) {
        Write-Warning "The certificate object includes a private key locally. The script uploads only the public RawData bytes, but you should normally pass a public .cer/.crt/.pem file."
    }

    return $certificate
}

function Get-UniqueValues {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Values
    )

    return @($Values | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique)
}

Assert-Module -Name "Microsoft.Graph.Authentication"
Assert-Module -Name "Microsoft.Graph.Applications"

$GraphResourceAppId = "00000003-0000-0000-c000-000000000000"

$PermissionProfiles = [ordered]@{
    IdentityBaseline = @(
        "Application.Read.All",
        "AuditLog.Read.All",
        "Directory.Read.All",
        "DirectoryRecommendations.Read.All",
        "EntitlementManagement.Read.All",
        "IdentityProvider.Read.All",
        "IdentityRiskEvent.Read.All",
        "OnPremDirectorySynchronization.Read.All",
        "Policy.Read.All",
        "Policy.Read.ConditionalAccess",
        "ProvisioningLog.Read.All",
        "Reports.Read.All",
        "ReportSettings.Read.All",
        "RoleManagement.Read.All",
        "UserAuthenticationMethod.Read.All"
    )

    PIM = @(
        "PrivilegedAccess.Read.AzureAD",
        "PrivilegedAccess.Read.AzureADGroup",
        "PrivilegedAccess.Read.AzureResources",
        "RoleEligibilitySchedule.Read.Directory",
        "RoleManagementAlert.Read.Directory"
    )

    M365Audit = @(
        "AuditLogsQuery.Read.All",
        "AuditLogsQuery-Exchange.Read.All",
        "AuditLogsQuery-OneDrive.Read.All",
        "AuditLogsQuery-SharePoint.Read.All",
        "ServiceActivity-Exchange.Read.All",
        "ServiceActivity-Microsoft365Web.Read.All",
        "ServiceActivity-OneDrive.Read.All",
        "ServiceActivity-Teams.Read.All",
        "OrgSettings-AppsAndServices.Read.All",
        "OrgSettings-Forms.Read.All",
        "SharePointTenantSettings.Read.All"
    )

    EndpointIntune = @(
        "BitlockerKey.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementRBAC.Read.All",
        "DeviceManagementServiceConfig.Read.All"
    )

    GlobalSecureAccess = @(
        "NetworkAccess.Read.All"
    )

    DefenderHunting = @(
        "SecurityIdentitiesHealth.Read.All",
        "SecurityIdentitiesSensors.Read.All",
        "SecurityIncident.Read.All",
        "ThreatHunting.Read.All"
    )
}

$SelectedProfiles = @()

if ($Profiles -contains "All") {
    $SelectedProfiles = @($PermissionProfiles.Keys)
}
else {
    $SelectedProfiles = $Profiles
}

$RequestedPermissionNames = @()

foreach ($profile in $SelectedProfiles) {
    if (-not $PermissionProfiles.Contains($profile)) {
        throw "Unknown permission profile: $profile"
    }

    $RequestedPermissionNames += $PermissionProfiles[$profile]
}

$RequestedPermissionNames += $AdditionalApplicationPermissions
$RequestedPermissionNames = Get-UniqueValues -Values $RequestedPermissionNames

if ($RequestedPermissionNames.Count -eq 0) {
    throw "No Microsoft Graph application permissions were selected."
}

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan

$ConnectScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
)

if ($TenantId) {
    Connect-MgGraph -TenantId $TenantId -Scopes $ConnectScopes -NoWelcome
}
else {
    Connect-MgGraph -Scopes $ConnectScopes -NoWelcome
}

$Context = Get-MgContext

if (-not $Context) {
    throw "Microsoft Graph connection failed."
}

Write-Host "Connected tenant: $($Context.TenantId)" -ForegroundColor Cyan

$EscapedDisplayName = Escape-ODataString -Value $DisplayName
$ExistingApps = @(Get-MgApplication -Filter "displayName eq '$EscapedDisplayName'" -Property "id,appId,displayName" -All)

if ($ExistingApps.Count -gt 0 -and -not $AllowDuplicateDisplayName) {
    $ExistingSummary = $ExistingApps | Select-Object DisplayName, AppId, Id | Format-Table | Out-String
    throw "An application with this display name already exists. Use -AllowDuplicateDisplayName to continue.`n$ExistingSummary"
}

Write-Host "Loading Microsoft Graph service principal..." -ForegroundColor Cyan

$GraphServicePrincipal = Get-MgServicePrincipal `
    -Filter "appId eq '$GraphResourceAppId'" `
    -Property "id,appId,displayName,appRoles" `
    -ConsistencyLevel eventual

if (-not $GraphServicePrincipal) {
    throw "Could not locate the Microsoft Graph service principal in this tenant."
}

$GraphApplicationRolesByValue = @{}

foreach ($role in $GraphServicePrincipal.AppRoles) {
    if ($role.IsEnabled -and ($role.AllowedMemberTypes -contains "Application")) {
        $GraphApplicationRolesByValue[$role.Value] = $role
    }
}

$MissingApplicationPermissions = @()

foreach ($permissionName in $RequestedPermissionNames) {
    if (-not $GraphApplicationRolesByValue.ContainsKey($permissionName)) {
        $MissingApplicationPermissions += $permissionName
    }
}

if ($MissingApplicationPermissions.Count -gt 0) {
    $missingText = $MissingApplicationPermissions -join "`n  - "
    throw @"
The following requested permissions were not found as enabled Microsoft Graph application permissions in this tenant:

  - $missingText

This usually means one of the following:
  1. The permission name is delegated-only, not app-only.
  2. The permission has been renamed, retired, or is not available in this cloud.
  3. The tenant does not expose that workload permission.

Retry with a smaller profile set, or pass only confirmed app-only permissions using -AdditionalApplicationPermissions.
"@
}

$ResolvedApplicationRoles = foreach ($permissionName in $RequestedPermissionNames) {
    $GraphApplicationRolesByValue[$permissionName]
}

$ResourceAccess = foreach ($role in $ResolvedApplicationRoles) {
    @{
        id   = $role.Id
        type = "Role"
    }
}

$RequiredResourceAccess = @(
    @{
        resourceAppId  = $GraphResourceAppId
        resourceAccess = @($ResourceAccess)
    }
)

$Certificate = Get-PublicCertificate -Path $CertificatePath
$CertificateDisplayName = "collector-cert-$($Certificate.Thumbprint)"

$KeyCredential = @{
    type          = "AsymmetricX509Cert"
    usage         = "Verify"
    key           = $Certificate.RawData
    displayName   = $CertificateDisplayName
    startDateTime = $Certificate.NotBefore.ToUniversalTime()
    endDateTime   = $Certificate.NotAfter.ToUniversalTime()
}

$ApplicationBody = @{
    displayName            = $DisplayName
    signInAudience         = "AzureADMyOrg"
    requiredResourceAccess = $RequiredResourceAccess
    keyCredentials         = @($KeyCredential)
    description            = "Temporary app-only Microsoft Graph collection client for authorised Azure and Microsoft 365 security assessment. Remove after the assessment."
}

Write-Host "Creating app registration: $DisplayName" -ForegroundColor Cyan

if ($PSCmdlet.ShouldProcess($DisplayName, "Create app registration")) {
    $Application = New-MgApplication -BodyParameter $ApplicationBody
}
else {
    return
}

Write-Host "Created app registration." -ForegroundColor Green
Write-Host "Application client ID: $($Application.AppId)" -ForegroundColor Green
Write-Host "Application object ID: $($Application.Id)" -ForegroundColor Green

Write-Host "Creating service principal / enterprise application..." -ForegroundColor Cyan

try {
    $ServicePrincipal = New-MgServicePrincipal -AppId $Application.AppId
}
catch {
    Write-Warning "Service principal creation returned an error. Attempting lookup by AppId. Error: $($_.Exception.Message)"
    Start-Sleep -Seconds 5
    $ServicePrincipal = Get-MgServicePrincipal `
        -Filter "appId eq '$($Application.AppId)'" `
        -Property "id,appId,displayName,appRoleAssignments"
}

if (-not $ServicePrincipal) {
    throw "App registration was created, but the matching service principal could not be created or found."
}

Write-Host "Created service principal." -ForegroundColor Green
Write-Host "Service principal object ID: $($ServicePrincipal.Id)" -ForegroundColor Green

if ($NoGrant) {
    Write-Warning "NoGrant was specified. The app registration has configured API permissions, but application permissions have not been granted."

    $AdminConsentUrl = "https://login.microsoftonline.com/$($Context.TenantId)/adminconsent?client_id=$($Application.AppId)"

    Write-Host ""
    Write-Host "Admin consent URL:" -ForegroundColor Yellow
    Write-Host $AdminConsentUrl
}
else {
    Write-Host "Granting Microsoft Graph application permissions..." -ForegroundColor Cyan
    Write-Warning "Programmatic permission grants take effect immediately. Review the requested permissions before running this in production."

    $ExistingAssignments = @(
        Get-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $ServicePrincipal.Id `
            -All `
            -ErrorAction SilentlyContinue
    )

    foreach ($role in $ResolvedApplicationRoles) {
        $AlreadyAssigned = $ExistingAssignments | Where-Object {
            $_.ResourceId -eq $GraphServicePrincipal.Id -and $_.AppRoleId -eq $role.Id
        }

        if ($AlreadyAssigned) {
            Write-Host "Already granted: $($role.Value)" -ForegroundColor DarkYellow
            continue
        }

        $AssignmentBody = @{
            principalId = $ServicePrincipal.Id
            resourceId  = $GraphServicePrincipal.Id
            appRoleId   = $role.Id
        }

        Write-Host "Granting: $($role.Value)" -ForegroundColor Cyan

        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $ServicePrincipal.Id `
            -BodyParameter $AssignmentBody | Out-Null
    }

    Write-Host "Application permissions granted." -ForegroundColor Green
}

$Output = [ordered]@{
    TenantId                   = $Context.TenantId
    DisplayName                = $DisplayName
    ApplicationClientId        = $Application.AppId
    ApplicationObjectId        = $Application.Id
    ServicePrincipalObjectId   = $ServicePrincipal.Id
    CertificateThumbprint      = $Certificate.Thumbprint
    CertificateSubject         = $Certificate.Subject
    CertificateNotAfterUtc     = $Certificate.NotAfter.ToUniversalTime().ToString("u")
    Profiles                   = $SelectedProfiles
    GraphApplicationPermissions = $RequestedPermissionNames
    NoGrant                    = [bool]$NoGrant
    AppOnlyConnectCommand      = "Connect-MgGraph -TenantId `"$($Context.TenantId)`" -ClientId `"$($Application.AppId)`" -CertificateThumbprint `"$($Certificate.Thumbprint)`""
}

$SafeFileName = ($DisplayName -replace '[^a-zA-Z0-9._-]', '_')
$OutputPath = Join-Path -Path (Get-Location) -ChildPath "$SafeFileName.connection-details.json"

$Output | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "Complete." -ForegroundColor Green
Write-Host "Connection details written to: $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "Optional Windows Graph client command, if the matching private certificate is installed:" -ForegroundColor Cyan
Write-Host $Output.AppOnlyConnectCommand -ForegroundColor Yellow
