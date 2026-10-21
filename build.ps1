$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$output = Join-Path $root 'release'
New-Item -ItemType Directory -Path $output -Force | Out-Null
Add-Type -AssemblyName System.Drawing
$bitmap = New-Object System.Drawing.Bitmap 64,64
$g = [System.Drawing.Graphics]::FromImage($bitmap)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::FromArgb(0,117,104))
$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White),5
$g.DrawRectangle($pen,17,13,30,39)
$g.DrawLine($pen,25,23,39,23)
$g.DrawLine($pen,25,33,39,33)
$g.DrawLine($pen,25,43,34,43)
$icon = [System.Drawing.Icon]::FromHandle($bitmap.GetHicon())
$stream = [IO.File]::Create((Join-Path $output 'DataGate.ico'))
$icon.Save($stream)
$stream.Dispose(); $g.Dispose(); $pen.Dispose(); $bitmap.Dispose()
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:Microsoft.CSharp.dll /reference:System.Core.dll /reference:System.Xml.dll /win32manifest:"$root\app.manifest" /win32icon:"$output\DataGate.ico" /out:"$output\DataGate.exe" "$root\DataGate.cs" "$root\TrafficMonitor.cs" "$root\RelatedApps.cs"
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
Copy-Item -LiteralPath (Join-Path $output 'DataGate.exe') -Destination (Join-Path $output 'DataGate-Setup.exe') -Force
Get-Item (Join-Path $output 'DataGate.exe') | Select-Object FullName,Length
