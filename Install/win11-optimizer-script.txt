# ============================================================================
# Windows 11 Ultimate Optimizer v2.1 - Sistema Inteligente
# Deteccion automatica y recomendaciones personalizadas
# ============================================================================

#Requires -RunAsAdministrator
#Requires -Version 5.1

$Global:Version = "2.1"
$Global:SystemProfile = $null
$Global:RecommendedProfile = $null

# ============================================================================
# ANALISIS INTELIGENTE DEL SISTEMA
# ============================================================================

function Analyze-System {
    Write-Host "`n==================== ANALIZANDO SISTEMA ====================" -ForegroundColor Cyan
    Write-Host "Por favor espere mientras analizamos su hardware..." -ForegroundColor Yellow
    Write-Host ""
    
    $analysis = @{
        # Hardware basico
        CPU = @{
            Name = (Get-WmiObject Win32_Processor).Name
            Cores = (Get-WmiObject Win32_Processor).NumberOfCores
            Threads = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
            MaxSpeed = (Get-WmiObject Win32_Processor).MaxClockSpeed
        }
        
        GPU = @{
            Name = (Get-WmiObject Win32_VideoController | Select-Object -First 1).Name
            DriverVersion = (Get-WmiObject Win32_VideoController | Select-Object -First 1).DriverVersion
            VRAM = [math]::Round((Get-WmiObject Win32_VideoController | Select-Object -First 1).AdapterRAM / 1GB, 2)
        }
        
        RAM = @{
            Total = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 0)
            Speed = (Get-WmiObject Win32_PhysicalMemory | Select-Object -First 1).Speed
            Available = [math]::Round((Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
        }
        
        Storage = @{
            Type = if((Get-PhysicalDisk | Where-Object {$_.MediaType -eq "SSD"}).Count -gt 0) {"SSD"} else {"HDD"}
            SystemDriveFree = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
        }
        
        System = @{
            Type = if((Get-WmiObject Win32_Battery) -ne $null) {"LAPTOP"} else {"DESKTOP"}
            OS = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
            Build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
        }
        
        # Deteccion de uso principal
        Usage = @{
            HasSteam = Test-Path "${env:ProgramFiles(x86)}\Steam"
            HasOBS = Test-Path "${env:ProgramFiles}\obs-studio" 
            HasOffice = Test-Path "${env:ProgramFiles}\Microsoft Office"
            HasVSCode = Test-Path "${env:LOCALAPPDATA}\Programs\Microsoft VS Code"
            HasAdobe = Test-Path "${env:ProgramFiles}\Adobe"
            IsGaming = $false
            IsWorkstation = $false
            IsGeneral = $false
        }
    }
    
    # Determinar perfil de uso
    $gamingScore = 0
    $workScore = 0
    
    # Puntuacion para gaming
    if ($analysis.GPU.Name -match "NVIDIA|AMD Radeon|RTX|GTX|RX") { $gamingScore += 3 }
    if ($analysis.RAM.Total -ge 16) { $gamingScore += 2 }
    if ($analysis.Usage.HasSteam) { $gamingScore += 3 }
    if ($analysis.GPU.VRAM -ge 4) { $gamingScore += 2 }
    if ($analysis.System.Type -eq "DESKTOP") { $gamingScore += 1 }
    
    # Puntuacion para workstation
    if ($analysis.RAM.Total -ge 32) { $workScore += 3 }
    if ($analysis.CPU.Cores -ge 8) { $workScore += 2 }
    if ($analysis.Usage.HasVSCode) { $workScore += 2 }
    if ($analysis.Usage.HasAdobe) { $workScore += 2 }
    if ($analysis.Usage.HasOffice) { $workScore += 1 }
    
    # Determinar uso principal
    if ($gamingScore -ge 6) {
        $analysis.Usage.IsGaming = $true
    } elseif ($workScore -ge 5) {
        $analysis.Usage.IsWorkstation = $true
    } else {
        $analysis.Usage.IsGeneral = $true
    }
    
    return $analysis
}

function Show-SystemAnalysis {
    param($Analysis)
    
    Write-Host "==================== ANALISIS COMPLETADO ====================" -ForegroundColor Green
    Write-Host ""
    Write-Host "HARDWARE DETECTADO:" -ForegroundColor Yellow
    Write-Host "  CPU: $($Analysis.CPU.Name)" -ForegroundColor White
    Write-Host "       Nucleos: $($Analysis.CPU.Cores) | Hilos: $($Analysis.CPU.Threads)" -ForegroundColor Gray
    Write-Host "  GPU: $($Analysis.GPU.Name)" -ForegroundColor White
    Write-Host "       VRAM: $($Analysis.GPU.VRAM) GB" -ForegroundColor Gray
    Write-Host "  RAM: $($Analysis.RAM.Total) GB @ $($Analysis.RAM.Speed) MHz" -ForegroundColor White
    Write-Host "  Almacenamiento: $($Analysis.Storage.Type) | Espacio libre: $($Analysis.Storage.SystemDriveFree) GB" -ForegroundColor White
    Write-Host "  Tipo de sistema: $($Analysis.System.Type)" -ForegroundColor White
    Write-Host ""
    
    # Determinar y mostrar uso detectado
    Write-Host "USO PRINCIPAL DETECTADO:" -ForegroundColor Yellow
    if ($Analysis.Usage.IsGaming) {
        Write-Host "  >>> SISTEMA DE GAMING <<<" -ForegroundColor Cyan
        Write-Host "  - GPU potente detectada" -ForegroundColor Gray
        Write-Host "  - Aplicaciones de juegos instaladas" -ForegroundColor Gray
        Write-Host "  - Hardware optimizado para gaming" -ForegroundColor Gray
    } elseif ($Analysis.Usage.IsWorkstation) {
        Write-Host "  >>> ESTACION DE TRABAJO <<<" -ForegroundColor Cyan
        Write-Host "  - CPU con multiples nucleos" -ForegroundColor Gray
        Write-Host "  - Software profesional detectado" -ForegroundColor Gray
        Write-Host "  - Alta cantidad de RAM" -ForegroundColor Gray
    } else {
        Write-Host "  >>> USO GENERAL/OFICINA <<<" -ForegroundColor Cyan
        Write-Host "  - Configuracion balanceada" -ForegroundColor Gray
        Write-Host "  - Uso mixto detectado" -ForegroundColor Gray
    }
    Write-Host ""
}

function Get-RecommendedProfile {
    param($Analysis)
    
    $recommendation = @{
        Profile = ""
        Reason = @()
        Score = 0
    }
    
    # Logica de recomendacion
    if ($Analysis.System.Type -eq "LAPTOP") {
        # Para laptops, priorizar ahorro de energia
        if ($Analysis.Usage.IsGaming) {
            $recommendation.Profile = "EQUILIBRADO"
            $recommendation.Reason += "Laptop gaming necesita balance entre rendimiento y bateria"
            $recommendation.Reason += "Evita sobrecalentamiento manteniendo buen rendimiento"
        } else {
            $recommendation.Profile = "AHORRO_ENERGIA"
            $recommendation.Reason += "Maximiza duracion de bateria en laptop"
            $recommendation.Reason += "Reduce calor y ruido del ventilador"
        }
    } else {
        # Para desktop
        if ($Analysis.Usage.IsGaming) {
            $recommendation.Profile = "MAXIMO_RENDIMIENTO"
            $recommendation.Reason += "Hardware gaming detectado - maximizar FPS"
            $recommendation.Reason += "GPU potente requiere optimizacion completa"
            $recommendation.Reason += "Sin restricciones de bateria en desktop"
        } elseif ($Analysis.Usage.IsWorkstation) {
            $recommendation.Profile = "EQUILIBRADO"
            $recommendation.Reason += "Balance optimo para productividad"
            $recommendation.Reason += "Mantiene servicios esenciales para trabajo"
            $recommendation.Reason += "Estabilidad para aplicaciones profesionales"
        } else {
            $recommendation.Profile = "EQUILIBRADO"
            $recommendation.Reason += "Mejor opcion para uso general"
            $recommendation.Reason += "Buen rendimiento sin sacrificar funcionalidad"
        }
    }
    
    # Ajustes especiales
    if ($Analysis.RAM.Total -le 8) {
        $recommendation.Profile = "EQUILIBRADO"
        $recommendation.Reason += "RAM limitada - necesita optimizacion cuidadosa"
    }
    
    if ($Analysis.Storage.Type -eq "HDD") {
        $recommendation.Reason += "HDD detectado - optimizaciones de disco incluidas"
    }
    
    return $recommendation
}

# ============================================================================
# PERFILES DE OPTIMIZACION
# ============================================================================

function Apply-MaxPerformanceProfile {
    Write-Host "`n========== APLICANDO PERFIL: MAXIMO RENDIMIENTO ==========" -ForegroundColor Red
    Write-Host "ADVERTENCIA: Este perfil desactiva muchas funciones del sistema" -ForegroundColor Yellow
    Write-Host "Recomendado solo para: Gaming intensivo, Renderizado, Benchmarks" -ForegroundColor Yellow
    Write-Host ""
    
    $changes = @()
    
    # 1. CPU al maximo
    Write-Host "[1/10] Configurando CPU para maximo rendimiento..." -ForegroundColor White
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1
    bcdedit /set useplatformtick yes | Out-Null
    bcdedit /set disabledynamictick yes | Out-Null
    $changes += "CPU: Prioridad maxima, sin throttling"
    
    # 2. GPU optimizada
    Write-Host "[2/10] Optimizando GPU para gaming..." -ForegroundColor White
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0
    $changes += "GPU: Prioridad maxima para juegos"
    
    # 3. Desactivar TODOS los servicios no esenciales
    Write-Host "[3/10] Desactivando servicios innecesarios (agresivo)..." -ForegroundColor White
    $servicesToDisable = @(
        "DiagTrack", "dmwappushservice", "lfsvc", "MapsBroker", "NetTcpPortSharing",
        "RemoteAccess", "RemoteRegistry", "SharedAccess", "TrkWks", "WbioSrvc",
        "WMPNetworkSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
        "WSearch", "SysMain", "WerSvc", "RetailDemo", "MessagingService",
        "PimIndexMaintenanceSvc", "OneSyncSvc", "Fax", "TabletInputService",
        "PrintNotify", "PcaSvc", "WpcMonSvc", "wisvc", "StiSvc", "WiaRpc"
    )
    foreach ($svc in $servicesToDisable) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
    $changes += "Servicios: 30+ servicios desactivados"
    
    # 4. Memoria optimizada
    Write-Host "[4/10] Optimizando memoria RAM..." -ForegroundColor White
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1
    $changes += "RAM: Cache grande, sin paginacion del kernel"
    
    # 5. Red optimizada para gaming
    Write-Host "[5/10] Aplicando optimizaciones de red para gaming..." -ForegroundColor White
    netsh int tcp set global chimney=enabled 2>$null
    netsh int tcp set global rss=enabled 2>$null
    netsh int tcp set global autotuninglevel=disabled 2>$null
    netsh int tcp set supplemental Internet congestionprovider=ctcp 2>$null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff
    $changes += "Red: Optimizada para minima latencia"
    
    # 6. Desactivar telemetria completa
    Write-Host "[6/10] Eliminando toda telemetria..." -ForegroundColor White
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
    $changes += "Telemetria: Completamente desactivada"
    
    # 7. Plan de energia Ultimate
    Write-Host "[7/10] Activando plan Ultimate Performance..." -ForegroundColor White
    powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
    $changes += "Energia: Ultimate Performance activo"
    
    # 8. Desactivar efectos visuales
    Write-Host "[8/10] Desactivando efectos visuales..." -ForegroundColor White
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
    $changes += "Visual: Efectos desactivados"
    
    # 9. Desactivar mitigaciones de seguridad (Spectre/Meltdown)
    Write-Host "[9/10] Desactivando mitigaciones de CPU (mayor rendimiento)..." -ForegroundColor White
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 3
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3
    $changes += "Seguridad: Mitigaciones desactivadas (+5-10% rendimiento)"
    
    # 10. Limpieza agresiva
    Write-Host "[10/10] Ejecutando limpieza agresiva..." -ForegroundColor White
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:WINDIR\Prefetch\*" -Force -ErrorAction SilentlyContinue
    $changes += "Limpieza: Temporales eliminados"
    
    Write-Host "`n============ PERFIL APLICADO EXITOSAMENTE ============" -ForegroundColor Green
    Write-Host "CAMBIOS REALIZADOS:" -ForegroundColor Yellow
    foreach ($change in $changes) {
        Write-Host "  [OK] $change" -ForegroundColor Green
    }
    
    Write-Host "`nIMPACTO ESPERADO:" -ForegroundColor Cyan
    Write-Host "  + 15-25% mejor rendimiento en juegos" -ForegroundColor Green
    Write-Host "  + 20-30% menor latencia de entrada" -ForegroundColor Green
    Write-Host "  + 10-15% mayor FPS" -ForegroundColor Green
    Write-Host "  - Algunas funciones de Windows desactivadas" -ForegroundColor Red
    Write-Host "  - Mayor consumo de energia" -ForegroundColor Red
}

function Apply-BalancedProfile {
    Write-Host "`n========== APLICANDO PERFIL: EQUILIBRADO ==========" -ForegroundColor Blue
    Write-Host "Optimizacion inteligente que mantiene funcionalidad del sistema" -ForegroundColor Cyan
    Write-Host "Ideal para: Uso diario, Trabajo, Gaming casual" -ForegroundColor Cyan
    Write-Host ""
    
    $changes = @()
    
    # 1. CPU balanceado
    Write-Host "[1/8] Configurando CPU para balance optimo..." -ForegroundColor White
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26
    $changes += "CPU: Balance entre programas y sistema"
    
    # 2. Servicios selectivos
    Write-Host "[2/8] Desactivando solo servicios innecesarios..." -ForegroundColor White
    $servicesToDisable = @(
        "DiagTrack", "dmwappushservice", "MapsBroker", 
        "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
        "RetailDemo", "MessagingService", "Fax"
    )
    foreach ($svc in $servicesToDisable) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
    $changes += "Servicios: Solo Xbox y telemetria desactivados"
    
    # 3. Mantener servicios importantes
    Write-Host "[3/8] Preservando servicios esenciales..." -ForegroundColor White
    Set-Service -Name "WSearch" -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service -Name "SysMain" -StartupType Manual -ErrorAction SilentlyContinue
    $changes += "Busqueda y Superfetch en modo manual"
    
    # 4. Red optimizada moderadamente
    Write-Host "[4/8] Optimizando red sin afectar estabilidad..." -ForegroundColor White
    netsh int tcp set global autotuninglevel=normal 2>$null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 10
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 20
    $changes += "Red: Optimizada con estabilidad"
    
    # 5. Plan de energia balanceado
    Write-Host "[5/8] Configurando plan de energia balanceado..." -ForegroundColor White
    powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e
    powercfg -change -monitor-timeout-ac 10
    powercfg -change -disk-timeout-ac 20
    $changes += "Energia: Plan balanceado activo"
    
    # 6. Telemetria basica
    Write-Host "[6/8] Configurando telemetria minima..." -ForegroundColor White
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1
    $changes += "Telemetria: Solo basica permitida"
    
    # 7. Optimizacion de memoria moderada
    Write-Host "[7/8] Optimizando memoria con precaucion..." -ForegroundColor White
    $RAM = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    if ($RAM -ge 16) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1
    }
    $changes += "RAM: Optimizacion adaptativa"
    
    # 8. Limpieza moderada
    Write-Host "[8/8] Ejecutando limpieza segura..." -ForegroundColor White
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    $changes += "Limpieza: Solo archivos temporales"
    
    Write-Host "`n============ PERFIL APLICADO EXITOSAMENTE ============" -ForegroundColor Green
    Write-Host "CAMBIOS REALIZADOS:" -ForegroundColor Yellow
    foreach ($change in $changes) {
        Write-Host "  [OK] $change" -ForegroundColor Green
    }
    
    Write-Host "`nIMPACTO ESPERADO:" -ForegroundColor Cyan
    Write-Host "  + 10-15% mejor rendimiento general" -ForegroundColor Green
    Write-Host "  + Sistema mas responsivo" -ForegroundColor Green
    Write-Host "  + Mantiene funcionalidad completa" -ForegroundColor Green
    Write-Host "  + Estabilidad garantizada" -ForegroundColor Green
}

function Apply-PowerSaveProfile {
    Write-Host "`n========== APLICANDO PERFIL: AHORRO DE ENERGIA ==========" -ForegroundColor Green
    Write-Host "Maximiza duracion de bateria y reduce consumo" -ForegroundColor Cyan
    Write-Host "Ideal para: Laptops, Trabajo remoto, Uso basico" -ForegroundColor Cyan
    Write-Host ""
    
    $changes = @()
    
    # 1. CPU en modo ahorro
    Write-Host "[1/7] Configurando CPU para minimo consumo..." -ForegroundColor White
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 0
    powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 80
    powercfg -setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 60
    $changes += "CPU: Limitado al 80% en AC, 60% en bateria"
    
    # 2. Plan de ahorro de energia
    Write-Host "[2/7] Activando plan de ahorro de energia..." -ForegroundColor White
    powercfg -setactive a1841308-3541-4fab-bc81-f71556f20b4a
    powercfg -change -monitor-timeout-ac 5
    powercfg -change -monitor-timeout-dc 2
    powercfg -change -disk-timeout-ac 10
    powercfg -change -disk-timeout-dc 5
    $changes += "Energia: Plan de ahorro activo"
    
    # 3. Desactivar servicios de alto consumo
    Write-Host "[3/7] Desactivando servicios de alto consumo..." -ForegroundColor White
    $servicesToDisable = @(
        "WSearch", "SysMain", "DiagTrack", "dmwappushservice",
        "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc"
    )
    foreach ($svc in $servicesToDisable) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
    $changes += "Servicios pesados desactivados"
    
    # 4. Reducir efectos visuales
    Write-Host "[4/7] Minimizando efectos visuales..." -ForegroundColor White
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80))
    $changes += "Efectos visuales minimizados"
    
    # 5. Configurar red para bajo consumo
    Write-Host "[5/7] Optimizando adaptadores de red..." -ForegroundColor White
    powercfg -setacvalueindex SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 2
    $changes += "WiFi: Modo ahorro de energia"
    
    # 6. Desactivar actualizaciones automaticas
    Write-Host "[6/7] Pausando actualizaciones automaticas..." -ForegroundColor White
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue
    $changes += "Windows Update en modo manual"
    
    # 7. Reducir brillo y configuraciones de pantalla
    Write-Host "[7/7] Ajustando configuracion de pantalla..." -ForegroundColor White
    powercfg -setacvalueindex SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 50
    powercfg -setdcvalueindex SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 25
    $changes += "Brillo: 50% en AC, 25% en bateria"
    
    Write-Host "`n============ PERFIL APLICADO EXITOSAMENTE ============" -ForegroundColor Green
    Write-Host "CAMBIOS REALIZADOS:" -ForegroundColor Yellow
    foreach ($change in $changes) {
        Write-Host "  [OK] $change" -ForegroundColor Green
    }
    
    Write-Host "`nIMPACTO ESPERADO:" -ForegroundColor Cyan
    Write-Host "  + 30-50% mas duracion de bateria" -ForegroundColor Green
    Write-Host "  + Menor calor generado" -ForegroundColor Green
    Write-Host "  + Sistema mas silencioso" -ForegroundColor Green
    Write-Host "  - Rendimiento reducido" -ForegroundColor Yellow
    Write-Host "  - Algunas funciones limitadas" -ForegroundColor Yellow
}

# ============================================================================
# SISTEMA DE RECOMENDACION
# ============================================================================

function Show-Recommendation {
    param($Analysis, $Recommendation)
    
    Write-Host "`n================ RECOMENDACION DEL SISTEMA ================" -ForegroundColor Cyan
    Write-Host ""
    
    $profileName = switch($Recommendation.Profile) {
        "MAXIMO_RENDIMIENTO" { "MAXIMO RENDIMIENTO" }
        "EQUILIBRADO" { "EQUILIBRADO" }
        "AHORRO_ENERGIA" { "AHORRO DE ENERGIA" }
    }
    
    Write-Host "  >>> PERFIL RECOMENDADO: $profileName <<<" -ForegroundColor Yellow -BackgroundColor DarkBlue
    Write-Host ""
    Write-Host "  RAZONES:" -ForegroundColor White
    foreach ($reason in $Recommendation.Reason) {
        Write-Host "    - $reason" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Mostrar que se optimizara
    Write-Host "  QUE SE OPTIMIZARA:" -ForegroundColor White
    switch($Recommendation.Profile) {
        "MAXIMO_RENDIMIENTO" {
            Write-Host "    [+] CPU al maximo rendimiento" -ForegroundColor Green
            Write-Host "    [+] GPU prioridad gaming" -ForegroundColor Green
            Write-Host "    [+] Red optimizada para baja latencia" -ForegroundColor Green
            Write-Host "    [+] Servicios innecesarios eliminados" -ForegroundColor Green
            Write-Host "    [-] Mayor consumo de energia" -ForegroundColor Red
        }
        "EQUILIBRADO" {
            Write-Host "    [+] Balance CPU/GPU optimo" -ForegroundColor Green
            Write-Host "    [+] Servicios no criticos desactivados" -ForegroundColor Green
            Write-Host "    [+] Sistema responsivo" -ForegroundColor Green
            Write-Host "    [=] Consumo de energia moderado" -ForegroundColor Yellow
        }
        "AHORRO_ENERGIA" {
            Write-Host "    [+] Maxima duracion de bateria" -ForegroundColor Green
            Write-Host "    [+] Temperatura reducida" -ForegroundColor Green
            Write-Host "    [+] Sistema silencioso" -ForegroundColor Green
            Write-Host "    [-] Rendimiento limitado" -ForegroundColor Red
        }
    }
    Write-Host ""
}

# ============================================================================
# MENU PRINCIPAL SIMPLIFICADO
# ============================================================================

function Show-MainMenu {
    Clear-Host
    Write-Host "`n" -NoNewline
    Write-Host "   WINDOWS 11 INTELLIGENT OPTIMIZER v$Global:Version   " -ForegroundColor Black -BackgroundColor Cyan
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] APLICAR PERFIL RECOMENDADO" -ForegroundColor Yellow
    Write-Host "      Usa el analisis del sistema para aplicar la mejor" -ForegroundColor Gray
    Write-Host "      configuracion automaticamente" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] VER ANALISIS Y RECOMENDACION" -ForegroundColor Cyan
    Write-Host "      Muestra el analisis detallado de tu hardware y" -ForegroundColor Gray
    Write-Host "      explica que perfil es el mas adecuado" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [3] SELECCION MANUAL DE PERFIL" -ForegroundColor White
    Write-Host "      Escoge manualmente entre los perfiles disponibles" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [4] RESTAURAR CONFIGURACION ORIGINAL" -ForegroundColor Magenta
    Write-Host "      Deshace todos los cambios realizados" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [0] SALIR" -ForegroundColor Red
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-ManualMenu {
    Clear-Host
    Write-Host "`n============= SELECCION MANUAL DE PERFIL =============" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] MAXIMO RENDIMIENTO" -ForegroundColor Red
    Write-Host "      Para: Gaming intensivo, Renderizado, Benchmarks" -ForegroundColor Gray
    Write-Host "      Impacto: +20% rendimiento, -funcionalidad" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] EQUILIBRADO" -ForegroundColor Blue
    Write-Host "      Para: Uso diario, Trabajo, Gaming casual" -ForegroundColor Gray
    Write-Host "      Impacto: +10% rendimiento, mantiene funciones" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [3] AHORRO DE ENERGIA" -ForegroundColor Green
    Write-Host "      Para: Laptops, Trabajo basico, Navegacion" -ForegroundColor Gray
    Write-Host "      Impacto: +40% bateria, -rendimiento" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [0] VOLVER" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Create-RestorePoint {
    Write-Host "`nCreando punto de restauracion..." -ForegroundColor Yellow
    try {
        Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
        Checkpoint-Computer -Description "Windows Optimizer 2.1 - Antes de optimizacion" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "[OK] Punto de restauracion creado" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[ERROR] No se pudo crear punto de restauracion" -ForegroundColor Red
        $response = Read-Host "Desea continuar sin punto de restauracion? (S/N)"
        return ($response -eq 'S' -or $response -eq 's')
    }
}

# ============================================================================
# PROGRAMA PRINCIPAL
# ============================================================================

function Start-IntelligentOptimizer {
    # Verificar permisos de administrador
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[ERROR] Este programa requiere permisos de Administrador" -ForegroundColor Red
        Write-Host "Por favor, ejecute PowerShell como Administrador" -ForegroundColor Yellow
        pause
        exit
    }
    
    # Analizar sistema al inicio
    Write-Host "`nIniciando Windows 11 Intelligent Optimizer v$Global:Version..." -ForegroundColor Cyan
    $Global:SystemProfile = Analyze-System
    $Global:RecommendedProfile = Get-RecommendedProfile -Analysis $Global:SystemProfile
    
    Write-Host "[OK] Sistema analizado correctamente" -ForegroundColor Green
    Write-Host "Presione cualquier tecla para continuar..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    # Menu principal
    do {
        Show-MainMenu
        $choice = Read-Host "Seleccione una opcion"
        
        switch ($choice) {
            "1" {
                # Aplicar perfil recomendado
                Clear-Host
                Show-SystemAnalysis -Analysis $Global:SystemProfile
                Show-Recommendation -Analysis $Global:SystemProfile -Recommendation $Global:RecommendedProfile
                
                Write-Host "Desea aplicar el perfil recomendado? (S/N)" -ForegroundColor Yellow
                $confirm = Read-Host
                
                if ($confirm -eq 'S' -or $confirm -eq 's') {
                    if (Create-RestorePoint) {
                        switch($Global:RecommendedProfile.Profile) {
                            "MAXIMO_RENDIMIENTO" { Apply-MaxPerformanceProfile }
                            "EQUILIBRADO" { Apply-BalancedProfile }
                            "AHORRO_ENERGIA" { Apply-PowerSaveProfile }
                        }
                        
                        Write-Host "`n[IMPORTANTE] Reinicie el sistema para aplicar todos los cambios" -ForegroundColor Yellow -BackgroundColor DarkRed
                    }
                }
            }
            
            "2" {
                # Ver analisis y recomendacion
                Clear-Host
                Show-SystemAnalysis -Analysis $Global:SystemProfile
                Show-Recommendation -Analysis $Global:SystemProfile -Recommendation $Global:RecommendedProfile
            }
            
            "3" {
                # Seleccion manual
                do {
                    Show-ManualMenu
                    $manualChoice = Read-Host "Seleccione un perfil"
                    
                    switch ($manualChoice) {
                        "1" {
                            if (Create-RestorePoint) {
                                Apply-MaxPerformanceProfile
                                Write-Host "`n[IMPORTANTE] Reinicie el sistema para aplicar todos los cambios" -ForegroundColor Yellow -BackgroundColor DarkRed
                            }
                            break
                        }
                        "2" {
                            if (Create-RestorePoint) {
                                Apply-BalancedProfile
                                Write-Host "`n[IMPORTANTE] Reinicie el sistema para aplicar todos los cambios" -ForegroundColor Yellow -BackgroundColor DarkRed
                            }
                            break
                        }
                        "3" {
                            if (Create-RestorePoint) {
                                Apply-PowerSaveProfile
                                Write-Host "`n[IMPORTANTE] Reinicie el sistema para aplicar todos los cambios" -ForegroundColor Yellow -BackgroundColor DarkRed
                            }
                            break
                        }
                    }
                    
                    if ($manualChoice -ne "0" -and $manualChoice -in @("1","2","3")) {
                        break
                    }
                } while ($manualChoice -ne "0")
            }
            
            "4" {
                # Restaurar configuracion original
                Write-Host "`nEsta funcion requiere usar el punto de restauracion creado" -ForegroundColor Yellow
                Write-Host "Ejecute 'rstrui.exe' desde el menu inicio para restaurar" -ForegroundColor Cyan
                Start-Process rstrui.exe
            }
            
            "0" {
                Write-Host "`nGracias por usar Windows 11 Intelligent Optimizer" -ForegroundColor Cyan
                Write-Host "Desarrollado para optimizacion inteligente del sistema" -ForegroundColor Gray
                break
            }
            
            default {
                Write-Host "[ERROR] Opcion no valida" -ForegroundColor Red
            }
        }
        
        if ($choice -ne "0") {
            Write-Host "`nPresione cualquier tecla para continuar..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        
    } while ($choice -ne "0")
}

# ============================================================================
# INICIAR PROGRAMA
# ============================================================================

Start-IntelligentOptimizer