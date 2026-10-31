$ErrorActionPreference = 'Stop'

$launcherPath = Join-Path $PSScriptRoot '..\run-trusted-device.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $launcherPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw "run-trusted-device.ps1 has PowerShell parse errors: $($parseErrors[0].Message)"
}

$parameter = $ast.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -eq 'TwoFactor'
} | Select-Object -First 1
if (-not $parameter) {
    throw 'The launcher must expose a TwoFactor parameter.'
}
if ($parameter.DefaultValue.Extent.Text -ne "'trusted-device'") {
    throw 'The launcher TwoFactor default must be trusted-device.'
}

$validateSet = $parameter.Attributes | Where-Object {
    $_.TypeName.FullName -eq 'ValidateSet'
} | Select-Object -First 1
if (-not $validateSet) {
    throw 'The launcher must restrict TwoFactor to supported choices.'
}
$allowed = @($validateSet.PositionalArguments | ForEach-Object { $_.Extent.Text.Trim("'").Trim('"') })
foreach ($choice in @('trusted-device', 'sms', 'sms-existing', 'circle')) {
    if ($choice -notin $allowed) {
        throw "The launcher is missing the supported TwoFactor choice '$choice'."
    }
}

$taskArgsAssignment = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -eq 'taskArgs'
}, $true) | Select-Object -First 1
$expectedTwoFactorArgument = [regex]::Escape("'-twofactor', `$TwoFactor")
if (-not $taskArgsAssignment -or $taskArgsAssignment.Right.Extent.Text -notmatch $expectedTwoFactorArgument) {
    throw 'The launcher must pass the selected TwoFactor value to trusted-device.exe.'
}

Write-Output 'run-trusted-device.ps1 offline parameter checks passed.'
