# Set Working Directory
Split-Path $MyInvocation.MyCommand.Path | Push-Location
[Environment]::CurrentDirectory = $PWD

Remove-Item "$env:RELOADEDIIMODS/legobatman.patches.demotag/*" -Force -Recurse
dotnet publish "./legobatman.patches.demotag.csproj" -c Release -o "$env:RELOADEDIIMODS/legobatman.patches.demotag" /p:OutputPath="./bin/Release" /p:ReloadedILLink="true"

# Restore Working Directory
Pop-Location