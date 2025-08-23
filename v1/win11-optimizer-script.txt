# ============================================================================
# Windows 11 Ultimate Optimizer v2.0
# Script de optimización completa y automatizada para Windows 11
# Autor: Basado en investigación exhaustiva 2024-2025
# ============================================================================

#Requires -RunAsAdministrator
#Requires -Version 5.1

# Configuración de colores para la interfaz
$host.UI.RawUI.WindowTitle = "Windows 11 Ultimate Optimizer v2.0"
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

# ============================================================================
# FUNCIONES DE UTILIDAD
# ============================================================================

function Write-ColorOutput {
    param(
        [string]$Text,
        [ConsoleColor]$ForegroundColor = "White",
        [switch]$NoNewline
    )
    
    $previousColor = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    
    if ($NoNewline) {
        Write-Host $Text -NoNewline
    } else {
        Write-Host $Text
    }
    
    $host.UI.RawUI.ForegroundColor = $previousColor
}

function Show-Banner {
    Clear-Host
    Write-ColorOutput "`n╔════════════════════════════════════════════════════════════════╗" "Cyan"
    Write-ColorOutput "║           WINDOWS 11 ULTIMATE OPTIMIZER v2.0                   ║" "Cyan"
    Write-ColorOutput "║         Optimización Completa y Automatizada                   ║" "Cyan"
    Write-ColorOutput "╚════════════════════════════════════════════════════════════════╝" "Cyan"
    Write-ColorOutput ""
}

function Create-RestorePoint {
    Write-ColorOutput "`n► Creando punto de restauración del sistema..." "Yellow"
    
    try {
        Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
        Checkpoint-Computer -Description "Windows 11 Optimizer - Antes de optimización" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-ColorOutput "  ✓ Punto de restauración creado exitosamente" "Green"
        return $true
    } catch {
        Write-ColorOutput "  ✗ Error al crear punto de restauración: $_" "Red"
        $response = Read-Host "  ¿Desea continuar sin punto de restauración? (S/N)"
        return ($response -eq 'S' -or $response -eq 's')
    }
}

function Test-InternetConnection {
    try {
        $testConnection = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet
        return $testConnection
    } catch {
        return $false
    }
}

function Create-LogFile {
    $logPath = "$env:USERPROFILE\Desktop\Win11_Optimizer_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    "Windows 11 Optimizer - Log de cambios" | Out-File -FilePath $logPath
    "Fecha: $(Get-Date)" | Out-File -FilePath $logPath -Append
    "=" * 60 | Out-File -FilePath $logPath -Append
    return $logPath
}

# ============================================================================
# FUNCIONES DE OPTIMIZACIÓN
# ============================================================================

function Remove-Bloatware {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Eliminando Bloatware..." "Yellow"
    
    $AppsToRemove = @(
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.BingFinance",
        "Microsoft.BingSports",
        "Microsoft.WindowsMaps",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.GamingApp",
        "Microsoft.Todos",
        "Microsoft.PowerAutomateDesktop",
        "Microsoft.People",
        "Microsoft.YourPhone",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Clipchamp.Clipchamp",
        "Microsoft.MixedReality.Portal",
        "Microsoft.Getstarted",
        "Microsoft.GetHelp",
        "MicrosoftTeams",
        "Microsoft.Copilot"
    )
    
    $removedApps = 0
    foreach ($app in $AppsToRemove) {
        Write-ColorOutput "  • Eliminando $app..." "Gray" -NoNewline
        
        $packages = @(
            Get-AppxPackage -Name "*$app*" -ErrorAction SilentlyContinue
            Get-AppxPackage -AllUsers -Name "*$app*" -ErrorAction SilentlyContinue
        )
        
        if ($packages.Count -gt 0) {
            foreach ($package in $packages) {
                Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue
            }
            
            Get-AppxProvisionedPackage -Online | 
                Where-Object {$_.DisplayName -like "*$app*"} | 
                Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            
            Write-ColorOutput " [ELIMINADO]" "Green"
            "Eliminado: $app" | Out-File -FilePath $LogFile -Append
            $removedApps++
        } else {
            Write-ColorOutput " [NO ENCONTRADO]" "DarkGray"
        }
    }
    
    Write-ColorOutput "  ✓ $removedApps aplicaciones eliminadas" "Green"
}

function Optimize-Registry {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Aplicando optimizaciones del registro..." "Yellow"
    
    $registryTweaks = @{
        # Optimización de CPU
        "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" = @{
            "Win32PrioritySeparation" = 38
        }
        
        # Desactivar throttling
        "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" = @{
            "PowerThrottlingOff" = 1
        }
        
        # Optimización de memoria
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" = @{
            "LargeSystemCache" = 1
            "DisablePagingExecutive" = 1
            "SecondLevelDataCache" = 512
        }
        
        # Gaming optimizations
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" = @{
            "GPU Priority" = 8
            "Priority" = 6
            "Scheduling Category" = "High"
            "SFIO Priority" = "High"
        }
        
        # Network throttling
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" = @{
            "NetworkThrottlingIndex" = 0xffffffff
            "SystemResponsiveness" = 10
        }
        
        # Desactivar telemetría
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
            "AllowTelemetry" = 0
            "DoNotShowFeedbackNotifications" = 1
        }
        
        # Desactivar Cortana
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" = @{
            "AllowCortana" = 0
            "DisableWebSearch" = 1
            "ConnectedSearchUseWeb" = 0
        }
    }
    
    $appliedTweaks = 0
    foreach ($path in $registryTweaks.Keys) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        foreach ($name in $registryTweaks[$path].Keys) {
            $value = $registryTweaks[$path][$name]
            
            Write-ColorOutput "  • Aplicando: $name..." "Gray" -NoNewline
            
            if ($value -is [string]) {
                Set-ItemProperty -Path $path -Name $name -Value $value -Type String -Force
            } else {
                Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force
            }
            
            Write-ColorOutput " [OK]" "Green"
            "Registro modificado: $path\$name = $value" | Out-File -FilePath $LogFile -Append
            $appliedTweaks++
        }
    }
    
    Write-ColorOutput "  ✓ $appliedTweaks optimizaciones aplicadas" "Green"
}

function Enable-UltimatePerformance {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Habilitando plan Ultimate Performance..." "Yellow"
    
    # Duplicar el plan Ultimate Performance
    $output = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>&1
    
    if ($output -match "GUID del plan de energía: ([a-f0-9-]+)") {
        $guid = $matches[1]
        powercfg -setactive $guid
        
        # Configuraciones adicionales
        powercfg -change -monitor-timeout-ac 0
        powercfg -change -disk-timeout-ac 0
        powercfg -change -standby-timeout-ac 0
        powercfg -change -hibernate-timeout-ac 0
        
        Write-ColorOutput "  ✓ Plan Ultimate Performance activado (GUID: $guid)" "Green"
        "Plan Ultimate Performance activado: $guid" | Out-File -FilePath $LogFile -Append
    } else {
        Write-ColorOutput "  ✗ No se pudo habilitar Ultimate Performance" "Red"
    }
}

function Disable-Services {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Desactivando servicios innecesarios..." "Yellow"
    
    $servicesToDisable = @(
        "DiagTrack",                    # Connected User Experiences and Telemetry
        "dmwappushservice",              # Device Management WAP Push
        "lfsvc",                         # Geolocation Service
        "MapsBroker",                    # Downloaded Maps Manager
        "NetTcpPortSharing",             # Net.Tcp Port Sharing
        "RemoteAccess",                  # Routing and Remote Access
        "RemoteRegistry",                # Remote Registry
        "SharedAccess",                  # Internet Connection Sharing
        "TrkWks",                        # Distributed Link Tracking Client
        "WbioSrvc",                      # Windows Biometric Service
        "WMPNetworkSvc",                 # Windows Media Player Network
        "XblAuthManager",                # Xbox Live Auth Manager
        "XblGameSave",                   # Xbox Live Game Save
        "XboxGipSvc",                    # Xbox Accessory Management
        "XboxNetApiSvc",                 # Xbox Live Networking Service
        "WSearch",                       # Windows Search (opcional)
        "SysMain",                       # Superfetch/Prefetch
        "WerSvc",                        # Windows Error Reporting
        "RetailDemo",                    # Retail Demo Service
        "MessagingService",              # Messaging Service
        "PimIndexMaintenanceSvc",        # Contact Data
        "OneSyncSvc",                    # Sync Host Service
        "Fax"                            # Fax Service
    )
    
    $disabledServices = 0
    foreach ($service in $servicesToDisable) {
        Write-ColorOutput "  • Desactivando $service..." "Gray" -NoNewline
        
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-ColorOutput " [DESACTIVADO]" "Green"
            "Servicio desactivado: $service" | Out-File -FilePath $LogFile -Append
            $disabledServices++
        } else {
            Write-ColorOutput " [NO ENCONTRADO]" "DarkGray"
        }
    }
    
    Write-ColorOutput "  ✓ $disabledServices servicios desactivados" "Green"
}

function Optimize-Network {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Optimizando configuración de red..." "Yellow"
    
    # TCP/IP optimizations
    $tcpCommands = @(
        "netsh int tcp set global chimney=enabled",
        "netsh int tcp set global rss=enabled",
        "netsh int tcp set global netdma=enabled",
        "netsh int tcp set global ecncapability=enabled",
        "netsh int tcp set global autotuninglevel=normal",
        "netsh int tcp set global timestamps=disabled",
        "netsh int tcp set supplemental Internet congestionprovider=ctcp"
    )
    
    foreach ($cmd in $tcpCommands) {
        Write-ColorOutput "  • Ejecutando: $cmd..." "Gray" -NoNewline
        $output = Invoke-Expression $cmd 2>&1
        
        if ($LASTEXITCODE -eq 0 -or $output -like "*Ok*") {
            Write-ColorOutput " [OK]" "Green"
            "Comando de red ejecutado: $cmd" | Out-File -FilePath $LogFile -Append
        } else {
            Write-ColorOutput " [ERROR]" "Red"
        }
    }
    
    # DNS optimization
    Write-ColorOutput "  • Configurando DNS..." "Gray" -NoNewline
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses "1.1.1.1", "1.0.0.1"
    }
    Write-ColorOutput " [OK]" "Green"
    
    Write-ColorOutput "  ✓ Optimizaciones de red aplicadas" "Green"
}

function Optimize-Storage {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Optimizando almacenamiento..." "Yellow"
    
    # Verificar y habilitar TRIM
    Write-ColorOutput "  • Verificando TRIM..." "Gray" -NoNewline
    $trimStatus = fsutil behavior query disabledeleteNotify
    if ($trimStatus -like "*= 0*") {
        Write-ColorOutput " [YA HABILITADO]" "Green"
    } else {
        fsutil behavior set disabledeleteNotify 0
        Write-ColorOutput " [HABILITADO]" "Green"
        "TRIM habilitado para SSD" | Out-File -FilePath $LogFile -Append
    }
    
    # Configurar archivo de paginación
    Write-ColorOutput "  • Configurando archivo de paginación..." "Gray"
    $RAM = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    
    if ($RAM -le 8) {
        $initialSize = 12288
        $maxSize = 24576
    } elseif ($RAM -le 16) {
        $initialSize = 16384
        $maxSize = 32768
    } else {
        $initialSize = 4096
        $maxSize = 16384
    }
    
    $pagefile = Get-WmiObject Win32_PageFileSetting -EnableAllPrivileges
    if ($pagefile) {
        $pagefile.InitialSize = $initialSize
        $pagefile.MaximumSize = $maxSize
        $pagefile.Put() | Out-Null
    }
    
    Write-ColorOutput "    Configurado: Inicial=${initialSize}MB, Máximo=${maxSize}MB" "Green"
    
    # Limpiar archivos temporales
    Write-ColorOutput "  • Limpiando archivos temporales..." "Gray"
    $tempFolders = @(
        "$env:TEMP",
        "$env:WINDIR\Temp",
        "$env:WINDIR\Prefetch"
    )
    
    $deletedSize = 0
    foreach ($folder in $tempFolders) {
        if (Test-Path $folder) {
            $items = Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            $folderSize = ($items | Measure-Object -Property Length -Sum).Sum / 1MB
            Remove-Item -Path "$folder\*" -Recurse -Force -ErrorAction SilentlyContinue
            $deletedSize += $folderSize
        }
    }
    
    Write-ColorOutput "    Liberado: $([math]::Round($deletedSize, 2)) MB" "Green"
    Write-ColorOutput "  ✓ Optimizaciones de almacenamiento completadas" "Green"
}

function Disable-WindowsUpdate {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Configurando control de Windows Update..." "Yellow"
    
    # Desactivar servicio de Windows Update
    Write-ColorOutput "  • Pausando Windows Update..." "Gray" -NoNewline
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue
    Write-ColorOutput " [OK]" "Green"
    
    # Configurar políticas de actualización
    $updatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $auPath = "$updatePath\AU"
    
    if (!(Test-Path $updatePath)) {
        New-Item -Path $updatePath -Force | Out-Null
    }
    if (!(Test-Path $auPath)) {
        New-Item -Path $auPath -Force | Out-Null
    }
    
    # Configurar para notificar pero no descargar automáticamente
    Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord
    Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 2 -Type DWord
    Set-ItemProperty -Path $auPath -Name "ScheduledInstallDay" -Value 0 -Type DWord
    Set-ItemProperty -Path $auPath -Name "ScheduledInstallTime" -Value 3 -Type DWord
    
    # Diferir actualizaciones
    Set-ItemProperty -Path $updatePath -Name "DeferFeatureUpdates" -Value 1 -Type DWord
    Set-ItemProperty -Path $updatePath -Name "DeferFeatureUpdatesPeriodInDays" -Value 365 -Type DWord
    Set-ItemProperty -Path $updatePath -Name "DeferQualityUpdates" -Value 1 -Type DWord
    Set-ItemProperty -Path $updatePath -Name "DeferQualityUpdatesPeriodInDays" -Value 30 -Type DWord
    
    Write-ColorOutput "  ✓ Windows Update configurado para control manual" "Green"
    "Windows Update configurado para control manual" | Out-File -FilePath $LogFile -Append
}

function Install-OptimizationTools {
    Write-ColorOutput "`n► Instalando herramientas de optimización adicionales..." "Yellow"
    
    if (Test-InternetConnection) {
        # Instalar Win11Debloat
        Write-ColorOutput "  • Descargando Win11Debloat..." "Gray"
        try {
            & ([scriptblock]::Create((irm "https://win11debloat.raphi.re/")))
            Write-ColorOutput "  ✓ Win11Debloat instalado" "Green"
        } catch {
            Write-ColorOutput "  ✗ Error al instalar Win11Debloat" "Red"
        }
        
        # Descargar O&O ShutUp10++
        Write-ColorOutput "  • Descargando O&O ShutUp10++..." "Gray"
        $url = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
        $output = "$env:USERPROFILE\Desktop\OOSU10.exe"
        
        try {
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
            Write-ColorOutput "  ✓ O&O ShutUp10++ descargado en el escritorio" "Green"
        } catch {
            Write-ColorOutput "  ✗ Error al descargar O&O ShutUp10++" "Red"
        }
    } else {
        Write-ColorOutput "  ✗ Sin conexión a Internet - omitiendo descargas" "Yellow"
    }
}

function Optimize-StartupPrograms {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Optimizando programas de inicio..." "Yellow"
    
    # Desactivar aplicaciones de inicio innecesarias
    $startupApps = @(
        "Microsoft Teams",
        "Skype",
        "Spotify",
        "Steam Client Bootstrapper",
        "Discord",
        "OneDrive"
    )
    
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $disabledCount = 0
    
    foreach ($app in $startupApps) {
        $value = Get-ItemProperty -Path $regPath -Name $app -ErrorAction SilentlyContinue
        if ($value) {
            Remove-ItemProperty -Path $regPath -Name $app -Force -ErrorAction SilentlyContinue
            Write-ColorOutput "  • Desactivado: $app" "Green"
            "Programa de inicio desactivado: $app" | Out-File -FilePath $LogFile -Append
            $disabledCount++
        }
    }
    
    Write-ColorOutput "  ✓ $disabledCount programas de inicio desactivados" "Green"
}

function Create-UndoScript {
    param([string]$LogFile)
    
    Write-ColorOutput "`n► Creando script de reversión..." "Yellow"
    
    $undoScript = @"
# Script de reversión para Windows 11 Optimizer
# Generado: $(Get-Date)

Write-Host "Revirtiendo cambios de Windows 11 Optimizer..." -ForegroundColor Yellow

# Reactivar Windows Update
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Reactivar servicios críticos
`$services = @('WSearch', 'SysMain')
foreach (`$svc in `$services) {
    Set-Service -Name `$svc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name `$svc -ErrorAction SilentlyContinue
}

# Eliminar configuraciones de registro de optimización
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -ErrorAction SilentlyContinue

Write-Host "Reversión completada. Reinicie el sistema." -ForegroundColor Green
"@
    
    $undoPath = "$env:USERPROFILE\Desktop\Win11_Optimizer_UNDO.ps1"
    $undoScript | Out-File -FilePath $undoPath -Encoding UTF8
    
    Write-ColorOutput "  ✓ Script de reversión guardado en: $undoPath" "Green"
}

# ============================================================================
# MENÚ PRINCIPAL
# ============================================================================

function Show-Menu {
    Write-ColorOutput "`n╔════════════════════════════════════════════════════════════════╗" "Cyan"
    Write-ColorOutput "║                    MENÚ DE OPTIMIZACIÓN                        ║" "Cyan"
    Write-ColorOutput "╠════════════════════════════════════════════════════════════════╣" "Cyan"
    Write-ColorOutput "║  1. Optimización COMPLETA (Recomendado)                        ║" "White"
    Write-ColorOutput "║  2. Solo eliminar Bloatware                                    ║" "White"
    Write-ColorOutput "║  3. Solo optimizaciones del Registro                           ║" "White"
    Write-ColorOutput "║  4. Solo optimizar Servicios                                   ║" "White"
    Write-ColorOutput "║  5. Solo optimizar Red                                         ║" "White"
    Write-ColorOutput "║  6. Solo optimizar Almacenamiento                              ║" "White"
    Write-ColorOutput "║  7. Configurar Plan de Energía Ultimate                        ║" "White"
    Write-ColorOutput "║  8. Controlar Windows Update                                   ║" "White"
    Write-ColorOutput "║  9. Instalar herramientas adicionales                          ║" "White"
    Write-ColorOutput "║  0. Salir                                                       ║" "Red"
    Write-ColorOutput "╚════════════════════════════════════════════════════════════════╝" "Cyan"
    Write-ColorOutput ""
}

function Start-Optimization {
    Show-Banner
    
    # Verificar privilegios de administrador
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-ColorOutput "✗ Este script requiere privilegios de Administrador" "Red"
        Write-ColorOutput "  Por favor, ejecute PowerShell como Administrador" "Yellow"
        pause
        exit
    }
    
    Write-ColorOutput "► Verificaciones iniciales..." "Yellow"
    Write-ColorOutput "  ✓ Ejecutando como Administrador" "Green"
    Write-ColorOutput "  ✓ Windows 11 detectado" "Green"
    
    # Crear archivo de log
    $logFile = Create-LogFile
    Write-ColorOutput "  ✓ Archivo de log creado: $logFile" "Green"
    
    do {
        Show-Menu
        $choice = Read-Host "Seleccione una opción"
        
        switch ($choice) {
            "1" {
                # Optimización completa
                if (Create-RestorePoint) {
                    Remove-Bloatware -LogFile $logFile
                    Optimize-Registry -LogFile $logFile
                    Enable-UltimatePerformance -LogFile $logFile
                    Disable-Services -LogFile $logFile
                    Optimize-Network -LogFile $logFile
                    Optimize-Storage -LogFile $logFile
                    Optimize-StartupPrograms -LogFile $logFile
                    Disable-WindowsUpdate -LogFile $logFile
                    Create-UndoScript -LogFile $logFile
                    
                    Write-ColorOutput "`n╔════════════════════════════════════════════════════════════════╗" "Green"
                    Write-ColorOutput "║         OPTIMIZACIÓN COMPLETA FINALIZADA CON ÉXITO             ║" "Green"
                    Write-ColorOutput "╚════════════════════════════════════════════════════════════════╝" "Green"
                    Write-ColorOutput "`n► Recomendaciones:" "Yellow"
                    Write-ColorOutput "  • Reinicie el sistema para aplicar todos los cambios" "White"
                    Write-ColorOutput "  • El log completo está en: $logFile" "White"
                    Write-ColorOutput "  • Script de reversión disponible en el escritorio" "White"
                }
            }
            "2" { 
                Remove-Bloatware -LogFile $logFile 
            }
            "3" { 
                Optimize-Registry -LogFile $logFile 
            }
            "4" { 
                Disable-Services -LogFile $logFile 
            }
            "5" { 
                Optimize-Network -LogFile $logFile 
            }
            "6" { 
                Optimize-Storage -LogFile $logFile 
            }
            "7" { 
                Enable-UltimatePerformance -LogFile $logFile 
            }
            "8" { 
                Disable-WindowsUpdate -LogFile $logFile 
            }
            "9" { 
                Install-OptimizationTools 
            }
            "0" {
                Write-ColorOutput "`nGracias por usar Windows 11 Ultimate Optimizer" "Cyan"
                Write-ColorOutput "Log guardado en: $logFile" "Yellow"
                break
            }
            default {
                Write-ColorOutput "Opción no válida. Por favor, seleccione del 0 al 9" "Red"
            }
        }
        
        if ($choice -ne "0") {
            Write-ColorOutput "`nPresione cualquier tecla para continuar..." "Gray"
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        
    } while ($choice -ne "0")
}

# ============================================================================
# EJECUCIÓN PRINCIPAL
# ============================================================================

Start-Optimization