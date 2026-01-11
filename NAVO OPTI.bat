<# :
@echo off
setlocal
cd /d "%~dp0"
title NOVA OPTI V5.7 - INITIALISATION...

:: 1. VERIFICATION ADMIN
fltmc >nul 2>&1 || (
    echo [!] Droits Administrateur requis. Relance en cours...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: 2. COPIE DE SECOURS
set "GhostScript=%temp%\Nova_Titan_%random%.ps1"
copy /y "%~f0" "%GhostScript%" >nul

:: 3. EXECUTION
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%GhostScript%'"

:: Si erreur, on pause pour voir
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] ERREUR CRITIQUE DETECTEE.
    pause
)

:: 4. NETTOYAGE
del /f /q "%GhostScript%" >nul
exit /b
#>

# --- DEBUT DU CODE POWERSHELL ---

try {
    # CONFIGURATION FENETRE
    $Host.UI.RawUI.WindowTitle = "NOVA OPTI V5.7 - TITAN FINAL STABLE"
    
    # VARIABLES
    $Version  = "5.7"
    $LogFile  = "$env:USERPROFILE\Desktop\nova_opti_log.txt"
    $ExportDir = "$env:USERPROFILE\Desktop\Nova_Backups"
    $Global:NeedsReboot = $false

    # COULEURS
    $C_Cyan   = "Cyan"
    $C_Green  = "Green"
    $C_Yellow = "Yellow"
    $C_White  = "White"
    $C_Red    = "Red"
    $S_Arrow  = ">>"
    $S_Box    = "#"

    # LANGUES
    $Global:LangCode = "FR" 

    $LangData = @{
        FR = @{
            TitleInfo = "ETAT DU SYSTEME"
            OptiStatus = "OPTIMISE A"
            Version = "VERSION PS"
            RebootReq = "ETAT : REDEMARRAGE REQUIS"
            Sec1 = "SECTION 1 : PERFORMANCES"
            Sec2 = "SECTION 2 : RESEAU ET NETTOYAGE"
            Sec3 = "SECTION 3 : SYSTEME ET SECURITE"
            Opt1 = "GAMING BOOST       - FPS, Latence Reseau et Prio GPU"
            Opt2 = "PLAN PERFORMANCE   - Active le mode Performance Ultime"
            Opt3 = "UI RAPIDE          - Desactive les animations Windows"
            Opt4 = "RESEAU PRO         - DNS Cloudflare + Optimisation TCP"
            Opt5 = "NETTOYAGE          - Supprime les fichiers Temporaires"
            Opt6 = "SAUVEGARDE         - Creer un point de restauration"
            Opt7 = "ANTI-BLOAT         - Desactive mouchards et services"
            OptS = "VOIR SERVICES      - Etat actuel des services"
            Opt8 = "MODE JEU           - Active GameMode et DVR Off"
            Opt9 = "RESTAURER DEFAUTS  - Revenir aux reglages d'origine"
            Footer1 = "EXPORTER CONFIG"
            Footer2 = "IMPORTER CONFIG"
            Footer3 = "AIDE / A PROPOS"
            Footer4 = "VOIR LES LOGS"
            Footer5 = "REBOOT LE PC"
            Footer6 = "QUITTER"
            ActionPrompt = "VOTRE CHOIX"
            AlreadyApplied = "Optimisation deja appliquee."
            BackKey = "[B] RETOUR"
            InvalidInput = "SAISIE INVALIDE - ANNULATION"
            RecHardware = "DETECTION MATERIEL"
            RecYes = "RECOMMANDE POUR VOTRE CONFIG"
            RecNo = "DECONSEILLE POUR VOTRE CONFIG"
            RecNeu = "COMPATIBLE AVEC VOTRE CONFIG"
            Cleaning = "Nettoyage en cours..."
            CleanSpace = "Espace recupere :"
            Confirm = "Confirmer l'application ?"
            Loading = "Chargement en cours..."
            Checking = "Analyse..."
            FilesFound = "Fichiers inutiles trouves :"
            CleanAlready = "Systeme deja propre. Rien a faire."
        }
        EN = @{
            TitleInfo = "SYSTEM STATUS"
            OptiStatus = "OPTIMIZED AT"
            Version = "PS VERSION"
            RebootReq = "STATUS: REBOOT REQUIRED"
            Sec1 = "SECTION 1 : PERFORMANCE"
            Sec2 = "SECTION 2 : NETWORK AND CLEANUP"
            Sec3 = "SECTION 3 : SYSTEM AND SECURITY"
            Opt1 = "GAMING BOOST       - FPS, Network Latency and GPU Prio"
            Opt2 = "PERFORMANCE PLAN   - Enables Ultimate Performance mode"
            Opt3 = "FAST UI            - Disables Windows Animations"
            Opt4 = "PRO NETWORK        - Cloudflare DNS + TCP Optimization"
            Opt5 = "CLEANUP            - Deletes Temporary Files"
            Opt6 = "BACKUP             - Create a Restore Point"
            Opt7 = "ANTI-BLOAT         - Disables spying services"
            OptS = "VIEW SERVICES      - Current status of services"
            Opt8 = "GAME MODE          - Enables GameMode and DVR Off"
            Opt9 = "RESTORE DEFAULTS   - Revert to original settings"
            Footer1 = "EXPORT CONFIG"
            Footer2 = "IMPORT CONFIG"
            Footer3 = "HELP / ABOUT"
            Footer4 = "VIEW LOGS"
            Footer5 = "REBOOT PC"
            Footer6 = "QUIT SCRIPT"
            ActionPrompt = "YOUR CHOICE"
            AlreadyApplied = "Optimization already applied."
            BackKey = "[B] BACK"
            InvalidInput = "INVALID INPUT - CANCELED"
            RecHardware = "HARDWARE DETECTION"
            RecYes = "RECOMMENDED FOR YOUR SETUP"
            RecNo = "NOT RECOMMENDED FOR YOUR SETUP"
            RecNeu = "COMPATIBLE WITH YOUR SETUP"
            Cleaning = "Cleaning in progress..."
            CleanSpace = "Space recovered:"
            Confirm = "Confirm application?"
            Loading = "Loading..."
            Checking = "Analyzing..."
            FilesFound = "Junk files found:"
            CleanAlready = "System already clean. Nothing to do."
        }
        ES = @{
            TitleInfo = "ESTADO DEL SISTEMA"
            OptiStatus = "OPTIMIZADO AL"
            Version = "VERSION PS"
            RebootReq = "ESTADO: REINICIO REQUERIDO"
            Sec1 = "SECCION 1 : RENDIMIENTO"
            Sec2 = "SECCION 2 : RED Y LIMPIEZA"
            Sec3 = "SECCION 3 : SISTEMA Y SEGURIDAD"
            Opt1 = "GAMING BOOST       - FPS, Latencia de Red y Prio GPU"
            Opt2 = "PLAN RENDIMIENTO   - Activa el modo Maximo Rendimiento"
            Opt3 = "UI RAPIDA          - Desactiva animaciones de Windows"
            Opt4 = "RED PRO            - DNS Cloudflare + Opti TCP"
            Opt5 = "LIMPIEZA           - Elimina archivos temporales"
            Opt6 = "COPIA DE SEG.      - Crear punto de restauracion"
            Opt7 = "ANTI-BLOAT         - Desactiva espionaje"
            OptS = "VER SERVICIOS      - Estado actual de servicios"
            Opt8 = "MODO JUEGO         - Activa GameMode y DVR Off"
            Opt9 = "RESTAURAR DEFECTO  - Volver a config original"
            Footer1 = "EXPORTAR CONFIG"
            Footer2 = "IMPORTAR CONFIG"
            Footer3 = "AYUDA / ACERCA DE"
            Footer4 = "VER LOGS"
            Footer5 = "REINICIAR PC"
            Footer6 = "SALIR"
            ActionPrompt = "ACCION"
            AlreadyApplied = "Esta optimizacion ya esta aplicada."
            BackKey = "[B] ATRAS"
            InvalidInput = "ENTRADA INVALIDA - CANCELADO"
            RecHardware = "RECOMENDACION HARDWARE"
            RecYes = "RECOMENDADO"
            RecNo = "NO RECOMENDADO"
            RecNeu = "COMPATIBLE"
            Cleaning = "Limpieza..."
            CleanSpace = "Espacio recuperado:"
            Confirm = "Confirmar ?"
            Loading = "Cargando..."
            Checking = "Analisis..."
            FilesFound = "Archivos basura:"
            CleanAlready = "Sistema limpio."
        }
    }

    function T($Key) {
        if ($LangData.$Global:LangCode.ContainsKey($Key)) { return $LangData.$Global:LangCode.$Key }
        return "TEXT_ERROR"
    }

    function Write-Log($Message) {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "[$Timestamp] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }

    function Get-HardwareInfo {
        $CPU = "Standard CPU"
        $GPU = "Standard GPU"
        try {
            $proc = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
            if ($proc) { $CPU = $proc.Name }
            $vid = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
            if ($vid) { $GPU = $vid.Name }
        } catch {}
        return @{ CPU = $CPU; GPU = $GPU }
    }

    function Get-GlobalOptiScore {
        $Points = 0
        $Total = 5
        $g = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -ErrorAction SilentlyContinue
        if ($g.Win32PrioritySeparation -eq 26) { $Points++ }
        
        $p = powercfg /getactivescheme
        if ($p -match "e9a42b02-d5df-448d-aa00-03f14749eb61" -or $p -match "High" -or $p -match "Performance") { $Points++ }
        
        $v = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -ErrorAction SilentlyContinue
        if ($v) { $Points++ } 
        
        # Check Reseau via AutoTuningLevel
        $tcp = Get-NetTCPSetting -SettingName "Internet" -ErrorAction SilentlyContinue
        if ($tcp.AutoTuningLevelLocal -eq "Normal") { $Points++ }
        
        $gm = Get-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -ErrorAction SilentlyContinue
        if ($gm.AllowAutoGameMode -eq 1) { $Points++ }
        
        return [math]::Round(($Points / $Total) * 100)
    }

    function Show-SmartLoading($ActionName, $Steps) {
        Write-Host "`n  $S_Arrow $ActionName..." -ForegroundColor $C_Cyan
        Write-Log "Debut operation: $ActionName"
        $CurrentStep = 0
        $TotalSteps = $Steps.Count
        foreach ($Step in $Steps) {
            $CurrentStep++
            $Percent = [math]::Round(($CurrentStep / $TotalSteps) * 100)
            $BarLength = 20
            $Filled = [math]::Round(($Percent / 100) * $BarLength)
            if ($Filled -lt 0) { $Filled = 0 }
            $Bar = ($S_Box * $Filled).PadRight($BarLength, ' ')
            Write-Host "`r  TRAITEMENT : [$Bar] $Percent% - $Step" -NoNewline -ForegroundColor $C_Green
            Start-Sleep -Milliseconds 100
        }
        Write-Host "`n  OK OPERATION TERMINEE !" -ForegroundColor $C_Green
        Start-Sleep -Seconds 1
    }

    function Select-Language {
        Clear-Host
        Write-Host "==========================================================================" -ForegroundColor $C_Cyan
        Write-Host "   SELECT LANGUAGE / CHOISIR LA LANGUE" -ForegroundColor $C_Yellow
        Write-Host "==========================================================================" -ForegroundColor $C_Cyan
        Write-Host "   [1] Francais"
        Write-Host "   [2] English"
        Write-Host "   [3] Espanol"
        Write-Host "==========================================================================" -ForegroundColor $C_Cyan
        
        while ($true) {
            $l = Read-Host "> Selection "
            switch ($l) {
                "1" { $Global:LangCode = "FR"; return }
                "2" { $Global:LangCode = "EN"; return }
                "3" { $Global:LangCode = "ES"; return }
                default { Write-Host "Invalid/Invalide" -ForegroundColor $C_Red }
            }
        }
    }

    function Main-Menu {
        Select-Language
        Write-Host "`n   [+] OK: $(T Loading)" -ForegroundColor $C_Green

        while ($true) {
            $OptiScore = Get-GlobalOptiScore
            $ScoreColor = if ($OptiScore -ge 80) { $C_Green } elseif ($OptiScore -ge 50) { $C_Yellow } else { $C_Red }
            
            Clear-Host
            
            Write-Host @"
  _   _  _____  _   _   ___      _____  ______  _____  _____ 
 | \ | ||  _  || | | | / _ \    |  _  || ___ \|_   _||_   _|
 |  \| || | | || | | |/ /_\ \   | | | || |_/ /  | |    | |  
 | . ` || | | || | | ||  _  |   | | | ||  __/   | |    | |  
 | |\  |\ \_/ /\ \_/ /| | | |   \ \_/ /| |      | |   _| |_ 
 \_| \_/ \___/  \___/ \_| |_/    \___/ \_|      \_/   \___/ 

                   --- OPTIMIZED BY Imad Gadois ---
==========================================================================
"@ -ForegroundColor $C_Cyan

            Write-Host "   [ $(T TitleInfo) : " -NoNewline
            Write-Host "$(T OptiStatus) $OptiScore% " -ForegroundColor $ScoreColor -NoNewline
            Write-Host "| $(T Version) : $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) ]"
            Write-Host "" 

            if ($Global:NeedsReboot) {
                Write-Host "   [!] $(T RebootReq)" -ForegroundColor $C_Red
                Write-Host "==========================================================================" -ForegroundColor $C_Cyan
            }

            Write-Host "   [ $(T Sec1) ]" -ForegroundColor $C_Yellow
            Write-Host "   [1] $S_Arrow $(T Opt1)"
            Write-Host "   [2] $S_Arrow $(T Opt2)"
            Write-Host "   [3] $S_Arrow $(T Opt3)"
            
            Write-Host "`n   [ $(T Sec2) ]" -ForegroundColor $C_Yellow
            Write-Host "   [4] $S_Arrow $(T Opt4)"
            Write-Host "   [5] $S_Arrow $(T Opt5)"
            
            Write-Host "`n   [ $(T Sec3) ]" -ForegroundColor $C_Yellow
            Write-Host "   [6] $S_Arrow $(T Opt6)"
            Write-Host "   [7] $S_Arrow $(T Opt7)"
            Write-Host "   [S] $S_Arrow $(T OptS)"
            Write-Host "   [8] $S_Arrow $(T Opt8)"
            Write-Host "   [9] $S_Arrow $(T Opt9)"

            Write-Host "`n==========================================================================" -ForegroundColor $C_Cyan
            Write-Host "   [E] $(T Footer1)                [I] $(T Footer2)" -ForegroundColor $C_White
            Write-Host "   [H] $(T Footer3)                [L] $(T Footer4)" -ForegroundColor $C_White
            Write-Host "   [R] $(T Footer5)                   [Q] $(T Footer6)" -ForegroundColor $C_White
            Write-Host "==========================================================================" -ForegroundColor $C_Cyan

            $choice = Read-Host "`n> $(T ActionPrompt) "
            
            switch ($choice) {
                "1" { Gaming-Boost }
                "2" { Power-Boost }
                "3" { Visual-Boost }
                "4" { Network-Boost }
                "5" { Cleanup-Boost }
                "6" { Restore-Point }
                "7" { Anti-Bloat }
                "S" { Show-Service-Status }
                "8" { GameMode-Boost }
                "9" { Restore-Defaults }
                "E" { Export-Config }
                "I" { Import-Config }
                "H" { Show-About }
                "L" { Open-Logs }
                "R" { 
                    Write-Log "Reboot user request"
                    Write-Host "`n   [!] REDEMARRAGE EN COURS..." -ForegroundColor $C_Red
                    Start-Sleep -Seconds 1
                    & shutdown.exe /r /t 0 /f
                    exit
                }
                "Q" { exit }
                default { 
                    Write-Host "`n[!] $(T InvalidInput)" -ForegroundColor $C_Red
                    Start-Sleep -Seconds 1
                }
            }
        }
    }

    function Confirm-Action {
        Write-Host "`n[?] $(T Confirm) (Enter = OUI, B = $(T BackKey))" -ForegroundColor $C_Yellow
        $k = (Read-Host "> ").Trim()
        if ($k -eq "") { return $true }
        if ($k -eq "B" -or $k -eq "b") { return $false }
        Write-Host "   [X] $(T InvalidInput)" -ForegroundColor $C_Red
        Start-Sleep -Seconds 1
        return $false
    }

    function Open-Logs {
        if (Test-Path $LogFile) {
            $proc = Get-Process notepad -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -match "nova_opti_log" }
            if (-not $proc) { Invoke-Item $LogFile }
        } else {
            Write-Host "Aucun log." -ForegroundColor $C_Red; Start-Sleep -Seconds 1
        }
    }

    # --- OPTIONS ---

    function Gaming-Boost {
        Write-Host "`n   [~] $(T Checking)..." -ForegroundColor $C_Yellow
        $chk = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -ErrorAction SilentlyContinue
        if ($chk.Win32PrioritySeparation -eq 26) {
            Write-Host "`n>> $(T AlreadyApplied)" -ForegroundColor $C_Green; Start-Sleep -Seconds 2; return
        }
        $hw = Get-HardwareInfo
        Write-Host "`n   [ $(T RecHardware) ]" -ForegroundColor $C_Cyan
        Write-Host "   CPU: $($hw.CPU) | GPU: $($hw.GPU)"
        
        $SetHAGS = $null

        if ($hw.GPU -match "RTX|RX 5[0-9]{3}|RX 6[0-9]{3}|RX 7[0-9]{3}|GTX 1[0-9]{3}") {
            Write-Host "   $(T RecYes)" -ForegroundColor $C_Green
            
            # --- AJOUT HAGS POUR GPU RECENTS ---
            Write-Host "`n   [?] OPTION GPU : HAGS (Hardware Scheduling)" -ForegroundColor $C_Cyan
            Write-Host "   [1] ACTIVER (Recommande pour RTX 30/40 - Gain FPS)"
            Write-Host "   [2] DESACTIVER (Recommande si jeux instables)"
            Write-Host "   [ENTER] Ne rien changer"
            $hags = Read-Host "   > Choix "
            if ($hags -eq "1") { $SetHAGS = 2 }
            if ($hags -eq "2") { $SetHAGS = 1 }
            # -----------------------------------
        } else {
            Write-Host "   $(T RecNeu)" -ForegroundColor $C_Yellow
        }

        if (!(Confirm-Action)) { return }
        $Steps = @("Registry: Win32PrioritySeparation", "Registry: NetworkThrottling", "Power: IdleDisable", "System: GPU Priority")
        if ($SetHAGS) { $Steps += "GPU: Update HAGS Mode" }

        Show-SmartLoading "Gaming Boost" $Steps
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF
        powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 1
        powercfg -setactive SCHEME_CURRENT
        
        if ($SetHAGS) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value $SetHAGS -ErrorAction SilentlyContinue
            Write-Log "HAGS HwSchMode defini sur $SetHAGS."
        }

        Write-Log "Gaming Boost applique."
        $Global:NeedsReboot = $true
    }

    function Power-Boost {
        Write-Host "`n   [~] $(T Checking)..." -ForegroundColor $C_Yellow
        $p = powercfg /getactivescheme
        if ($p -match "e9a42b02-d5df-448d-aa00-03f14749eb61") {
            Write-Host "`n>> $(T AlreadyApplied)" -ForegroundColor $C_Green; Start-Sleep -Seconds 2; return
        }
        if (!(Confirm-Action)) { return }
        $Steps = @("Import Scheme", "Activate Scheme", "Validate State")
        Show-SmartLoading "Plan Performance Titan" $Steps
        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
        powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61
        Write-Log "Power Plan Ultimate active."
    }

    function Visual-Boost {
        Write-Host "`n   [~] $(T Checking)..." -ForegroundColor $C_Yellow
        $v = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -ErrorAction SilentlyContinue
        if ($v.VisualFXSetting -eq 2) {
             Write-Host "`n>> $(T AlreadyApplied)" -ForegroundColor $C_Green; Start-Sleep -Seconds 2; return
        }
        if (!(Confirm-Action)) { return }
        $Steps = @("VisualFXSetting: Performance", "UserPreferencesMask: Update", "Explorer: Refresh")
        Show-SmartLoading "Optimisation Interface" $Steps
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -ErrorAction Stop
            Write-Log "Visual Boost applique."
            $Global:NeedsReboot = $true
        } catch {}
    }

    function Network-Boost {
        Write-Host "`n   [~] $(T Checking)..." -ForegroundColor $C_Yellow
        
        $tcp = Get-NetTCPSetting -SettingName "Internet" -ErrorAction SilentlyContinue
        if ($tcp.AutoTuningLevelLocal -eq "Normal" -and $tcp.Rss -eq "Enabled") {
             Write-Host "`n>> $(T AlreadyApplied)" -ForegroundColor $C_Green; Start-Sleep -Seconds 2; return
        }

        if (!(Confirm-Action)) { return }
        
        $Steps = @("TCP: AutoTuning Normal", "TCP: RSS Enabled", "TCP: ECN & Timestamps Off", "DNS: Cloudflare (1.1.1.1)", "Flush DNS Cache")
        Show-SmartLoading "Network Boost" $Steps
        
        netsh int tcp set global autotuninglevel=normal | Out-Null
        netsh int tcp set global rss=enabled | Out-Null
        netsh int tcp set global ecncapability=disabled | Out-Null
        netsh int tcp set global timestamps=disabled | Out-Null
        
        # DNS Safe Mode
        Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
            try { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses ('1.1.1.1','1.0.0.1') -ErrorAction SilentlyContinue } catch {}
        }
        ipconfig /flushdns | Out-Null
        Write-Log "Optimisation reseau appliquee (TCP Normal + RSS + ECN/Timestamps Off)."
    }

    function Cleanup-Boost {
        Write-Host "`n   [~] $(T Checking)..." -ForegroundColor $C_Yellow
        $TempPath = "$env:TEMP"
        $WinTemp = "C:\Windows\Temp"
        $SizeBefore = (Get-ChildItem $TempPath, $WinTemp -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
        $SizeBeforeRounded = [math]::Round($SizeBefore, 2)
        
        if ($SizeBefore -lt 1) {
             Write-Host "`n>> $(T CleanAlready)" -ForegroundColor $C_Green; Start-Sleep -Seconds 2; return
        }

        Write-Host "`n   >> $(T FilesFound) $SizeBeforeRounded MB" -ForegroundColor $C_White
        if (!(Confirm-Action)) { return }

        $Steps = @("Scan User Temp", "Scan System Temp", "Safe Delete", "Empty Recycle Bin")
        Show-SmartLoading "Smart Cleanup" $Steps

        Remove-Item -Path "$TempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$WinTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        
        Write-Host "`n   [OK] $(T CleanSpace) $SizeBeforeRounded MB" -ForegroundColor $C_Green
        Write-Log "Nettoyage: $SizeBeforeRounded MB liberes."
        Start-Sleep -Seconds 3
    }

    function Restore-Point {
        if (!(Confirm-Action)) { return }
        $Steps = @("Check VSS Service", "Enable System Restore", "Create Checkpoint")
        Show-SmartLoading "Backup System" $Steps
        try {
            Set-Service -Name "vss" -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name "vss" -ErrorAction SilentlyContinue
            Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
            Checkpoint-Computer -Description "Nova_Titan_Backup_V$Version" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Host "[+] Sauvegarde OK !" -ForegroundColor $C_Green
            Write-Log "Point de restauration cree."
        } catch {
            Write-Host "[!] ERREUR CRITIQUE: $_" -ForegroundColor $C_Red
        }
        Start-Sleep -Seconds 2
    }

    function Anti-Bloat {
        if (!(Confirm-Action)) { return }
        
        $Steps = @("Backup Services", "Stop DiagTrack", "Stop Xbox Services", "Disable Telemetry")
        Show-SmartLoading "Anti-Bloatware" $Steps
        
        $Services = @("DiagTrack", "dmwappushservice", "MapsBroker", "RetailDemo", "TrkWks", "XblAuthManager", "XblGameSave", "XboxNetApiSvc")
        
        # 1. Creation du Backup AVANT modification
        if (!(Test-Path $ExportDir)) { New-Item -Path $ExportDir -ItemType Directory -Force | Out-Null }
        $BackupFile = "$ExportDir\Services_Backup.xml"
        
        # Sauvegarde seulement s'il n'existe pas deja
        if (!(Test-Path $BackupFile)) {
            Get-Service -Name $Services -ErrorAction SilentlyContinue | Select-Object Name, StartType, Status | Export-Clixml -Path $BackupFile
            Write-Log "Backup services cree: $BackupFile"
        }

        # 2. Desactivation avec sc.exe (non-bloquant)
        foreach ($svc in $Services) {
            if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
                # Utilisation de sc.exe pour eviter le blocage 'pending stop'
                sc.exe stop $svc | Out-Null
                Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -ErrorAction SilentlyContinue
        Write-Log "Anti-Bloat applique."
        $Global:NeedsReboot = $true
    }

    function Show-Service-Status {
        Write-Host "`n   [ STATUS SERVICES ]" -ForegroundColor $C_Yellow
        $Services = @("DiagTrack", "dmwappushservice", "MapsBroker", "RetailDemo", "TrkWks", "XblAuthManager", "XblGameSave", "XboxNetApiSvc")
        foreach ($s in $Services) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($svc) {
                $color = if ($svc.Status -eq 'Running') { $C_Red } else { $C_Green }
                Write-Host "   - $($s.PadRight(20)) : " -NoNewline
                Write-Host "$($svc.Status)" -ForegroundColor $color
            } else {
                Write-Host "   - $($s.PadRight(20)) : ABSENT" -ForegroundColor $C_Gray
            }
        }
        Write-Host "`n   [B] $(T BackKey)"
        Read-Host
    }

    function GameMode-Boost {
        Write-Host "`n   [~] $(T Checking)..." -ForegroundColor $C_Yellow
        $chk = Get-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -ErrorAction SilentlyContinue
        if ($chk.AllowAutoGameMode -eq 1) {
            Write-Host "`n>> $(T AlreadyApplied)" -ForegroundColor $C_Green; Start-Sleep -Seconds 2; return
        }
        if (!(Confirm-Action)) { return }
        $Steps = @("GameBar: AutoGameMode On", "DVR: Disabled", "FSE Behavior: Optimized")
        Show-SmartLoading "Game Mode" $Steps
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2
        Write-Log "Game Mode active."
    }

    function Restore-Defaults {
        Write-Host "`n[!] ATTENTION: CECI ANNULE TOUTES LES OPTIMISATIONS" -ForegroundColor $C_Red
        if (!(Confirm-Action)) { return }
        
        $Steps = @("Priority: Default", "Throttling: Default", "Power: Balanced", "Services: Restore", "DNS: DHCP")
        Show-SmartLoading "Factory Reset" $Steps
        
        # 1. Registre
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 10
        powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e
        
        # 2. Reseau
        netsh int tcp set global autotuninglevel=normal | Out-Null
        netsh int tcp set global rss=enabled | Out-Null
        Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Set-DnsClientServerAddress -ResetServerAddresses
        
        # 3. Restauration Services depuis Backup
        $BackupFile = "$ExportDir\Services_Backup.xml"
        if (Test-Path $BackupFile) {
            try {
                $RestoredServices = Import-Clixml -Path $BackupFile
                foreach ($s in $RestoredServices) {
                    Set-Service -Name $s.Name -StartupType $s.StartType -ErrorAction SilentlyContinue
                    if ($s.Status -eq 'Running') { Start-Service -Name $s.Name -ErrorAction SilentlyContinue }
                }
                Write-Log "Services restaures depuis backup."
            } catch { Write-Log "Erreur lors de la restauration des services." }
        }

        Write-Log "Reset Factory applique."
        $Global:NeedsReboot = $true
    }

    function Export-Config {
        if (!(Test-Path $ExportDir)) { New-Item -Path $ExportDir -ItemType Directory -Force | Out-Null }
        $Date = Get-Date -Format "yyyyMMdd_HHmmss"
        reg export "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "$ExportDir\Backup_Priority_$Date.reg" /y | Out-Null
        Write-Host "`n[+] Config -> $ExportDir" -ForegroundColor $C_Green
        Start-Sleep -Seconds 2
    }

    function Import-Config {
        Write-Host "`n[!] DRAG AND DROP .REG FILE HERE" -ForegroundColor $C_Yellow
        $file = (Read-Host "> Path ").Trim('"')
        if ($file -match "B|b" -and $file.Length -lt 2) { return }
        if (Test-Path $file) {
            if ((Get-Content $file -TotalCount 1) -match "Windows Registry Editor") {
                reg import $file
                Write-Host "[+] OK !" -ForegroundColor $C_Green
            } else {
                Write-Host "[!] Invalid .reg" -ForegroundColor $C_Red
            }
        }
        Start-Sleep -Seconds 2
    }

    function Show-About {
        Clear-Host
        Write-Host "==========================================================================" -ForegroundColor $C_Cyan
        Write-Host "   AIDE & A PROPOS / HELP & ABOUT" -ForegroundColor $C_Yellow
        Write-Host "==========================================================================" -ForegroundColor $C_Cyan
        Write-Host "`n   [ A PROPOS ]" -ForegroundColor $C_Green
        Write-Host "   NOVA OPTI est un outil professionnel d'optimisation Windows."
        Write-Host "   Il reduit la latence, supprime la telemetrie et optimise le CPU/GPU."
        Write-Host "   Securite : Chaque action est reversible et verifiee."
        Write-Host "`n   Created by Imad Gadois" -ForegroundColor $C_White
        Write-Host "`n   [ AIDE - CONSEILS ]" -ForegroundColor $C_Green
        Write-Host "   1. Creez toujours un point de restauration (Option 6)."
        Write-Host "   2. Appliquez les options 1, 2, 4 pour le Gaming."
        Write-Host "   3. Le nettoyage (5) est sur (ne touche pas aux pilotes)."
        Write-Host "   4. Si un bug survient, utilisez l'option 9."
        Write-Host "`n   [B] $(T BackKey)"
        Read-Host
    }

    # --- INITIALISATION ---
    if (!(Test-Path $LogFile)) { New-Item -Path $LogFile -ItemType File -Force > $null }
    Write-Log "--- Demarrage NOVA OPTI V$Version ---"
    Main-Menu
} catch {
    Write-Host "`n[!!!] FATAL ERROR / ERREUR CRITIQUE [!!!]" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host "`nAppuyez sur Entree pour quitter..."
    Read-Host
}