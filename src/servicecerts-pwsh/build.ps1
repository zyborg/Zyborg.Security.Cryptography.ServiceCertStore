
$asmSrc = "$PSScriptRoot\..\Zyborg.Security.Cryptography\bin\Release\netstandard2.0\Zyborg.Security.Cryptography.dll"
$target = "$PSScriptRoot\ServiceCertStore\bin"

if (-not (Test-Path -PathType Container -Path $target)) {
    mkdir $target
}
cp -Force $asmSrc $target
