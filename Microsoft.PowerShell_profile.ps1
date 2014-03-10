# Fix up the default color scheme a bit ... black on white
# make the buffersize 3000 lines x 132 columns (must do this first)
# make the screen 51 x 132
# Modify the error, warning, debug, verbose and progress colors to be compatible with black on white
#
$a = (Get-Host).UI.RawUI


$a.BackgroundColor = "White"
$a.ForegroundColor = "Black"
$b = $a.BufferSize 
$b.Width 	= 132
$b.Height 	= 3000
$a.BufferSize = $b
$b = $a.WindowSize 
$b.Width 	= 132
$b.Height 	= 51
$a.WindowSize = $b


$a = (Get-Host).PrivateData

$a.ErrorForegroundColor    = "Red"
$a.ErrorBackgroundColor    = "Yellow"
$a.WarningForegroundColor  = "Yellow"
$a.WarningBackgroundColor  = "Blue"
$a.DebugForegroundColor    = "Yellow"
$a.DebugBackgroundColor    = "Black"
$a.VerboseForegroundColor  = "Yellow"
$a.VerboseBackgroundColor  = "DarkMagenta"
$a.ProgressForegroundColor = "Yellow"
$a.ProgressBackgroundColor = "Magenta"

[System.Collections.ArrayList]$DefaultCIServers = "put.com","your.com","list.com","here.com"
[System.Collections.ArrayList]$DefaultVIServers = "put.com","your.com","list.com","here.com"

$PowerCLI_Home = "C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts"
$PowerCLI_Init = $PowerCLI_Home+"/Initialize-PowerCLIEnvironment.ps1"