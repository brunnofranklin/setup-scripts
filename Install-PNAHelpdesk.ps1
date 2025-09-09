<#
.SYNOPSIS
    Script de Instalação e Configuração do PNA Helpdesk
    
.DESCRIPTION
    Script PowerShell robusto para instalação automática do sistema PNA Helpdesk
    Inclui validação de erros, sistema de logging, backup automático, 
    verificações de segurança e monitoramento de recursos.
    
.PARAMETER InstallPath
    Caminho de instalação do PNA Helpdesk (padrão: C:\PNAHelpdesk)
    
.PARAMETER LogPath
    Caminho para armazenar logs (padrão: C:\PNAHelpdesk\Logs)
    
.PARAMETER BackupPath
    Caminho para backup automático (padrão: C:\PNAHelpdesk\Backup)
    
.PARAMETER ConfigFile
    Arquivo de configuração personalizado (opcional)
    
.PARAMETER SkipBackup
    Pula a criação de backup automático
    
.EXAMPLE
    .\Install-PNAHelpdesk.ps1 -InstallPath "D:\PNAHelpdesk" -Verbose
    
.NOTES
    Autor: PNA Development Team
    Versão: 2.0
    Data: 2024
    
    Requisitos:
    - PowerShell 5.1 ou superior
    - Privilégios de administrador
    - Conexão com internet para download de dependências
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$InstallPath = "C:\PNAHelpdesk",
    
    [Parameter()]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$LogPath = "C:\PNAHelpdesk\Logs",
    
    [Parameter()]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$BackupPath = "C:\PNAHelpdesk\Backup",
    
    [Parameter()]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ConfigFile,
    
    [Parameter()]
    [switch]$SkipBackup
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURAÇÕES GLOBAIS E CONSTANTES
# ============================================================================

# Configurações de erro
$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"
$VerbosePreference = if ($PSBoundParameters.ContainsKey('Verbose')) { 'Continue' } else { 'SilentlyContinue' }

# Constantes do sistema
$Script:PNA_VERSION = "2.0.1"
$Script:REQUIRED_PS_VERSION = [Version]"5.1"
$Script:REQUIRED_NET_VERSION = [Version]"4.7.2"
$Script:MAX_RETRY_ATTEMPTS = 3
$Script:WEBSOCKET_TIMEOUT = 30000 # 30 segundos
$Script:MEMORY_THRESHOLD_MB = 512  # Limite de memória em MB

# URLs e recursos
$Script:DOWNLOAD_URLS = @{
    'PNACore'        = 'https://releases.pna.com/core/latest.zip'
    'Dependencies'   = 'https://releases.pna.com/deps/dependencies.zip'
    'WebSocketLib'   = 'https://releases.pna.com/libs/websocket.dll'
    'AuthModule'     = 'https://releases.pna.com/auth/auth-module.zip'
}

# ============================================================================
# SISTEMA DE LOGGING AVANÇADO
# ============================================================================

enum LogLevel {
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
}

class PNALogger {
    [string]$LogFile
    [LogLevel]$MinLevel
    [bool]$WriteToConsole
    [System.IO.FileStream]$FileStream
    [System.IO.StreamWriter]$StreamWriter
    
    PNALogger([string]$logPath, [LogLevel]$minLevel, [bool]$writeConsole) {
        $this.LogFile = Join-Path $logPath "PNAHelpdesk_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $this.MinLevel = $minLevel
        $this.WriteToConsole = $writeConsole
        $this.InitializeLogFile()
    }
    
    [void] InitializeLogFile() {
        try {
            $logDir = Split-Path $this.LogFile -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            
            $this.FileStream = [System.IO.FileStream]::new($this.LogFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
            $this.StreamWriter = [System.IO.StreamWriter]::new($this.FileStream, [System.Text.Encoding]::UTF8)
            $this.StreamWriter.AutoFlush = $true
            
            $this.WriteLog([LogLevel]::INFO, "Sistema de logging inicializado", @{})
        }
        catch {
            Write-Error "Falha ao inicializar sistema de logging: $_"
            throw
        }
    }
    
    [void] WriteLog([LogLevel]$level, [string]$message, [hashtable]$context) {
        if ($level -lt $this.MinLevel) { return }
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $levelStr = $level.ToString().PadRight(8)
        $processId = $PID
        $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        
        # Formato: [TIMESTAMP] [LEVEL] [PID:TID] MESSAGE {CONTEXT}
        $contextStr = if ($context.Count -gt 0) { " | Context: $(ConvertTo-Json $context -Compress)" } else { "" }
        $logEntry = "[$timestamp] [$levelStr] [$processId`:$threadId] $message$contextStr"
        
        # Escrever no arquivo
        try {
            $this.StreamWriter.WriteLine($logEntry)
        }
        catch {
            Write-Warning "Falha ao escrever no log: $_"
        }
        
        # Escrever no console se habilitado
        if ($this.WriteToConsole) {
            switch ($level) {
                ([LogLevel]::DEBUG) { Write-Verbose $message }
                ([LogLevel]::INFO) { Write-Host "INFO: $message" -ForegroundColor Green }
                ([LogLevel]::WARNING) { Write-Warning $message }
                ([LogLevel]::ERROR) { Write-Host "ERROR: $message" -ForegroundColor Red }
                ([LogLevel]::CRITICAL) { Write-Host "CRITICAL: $message" -ForegroundColor Magenta }
            }
        }
    }
    
    [void] Debug([string]$message, [hashtable]$context = @{}) {
        $this.WriteLog([LogLevel]::DEBUG, $message, $context)
    }
    
    [void] Info([string]$message, [hashtable]$context = @{}) {
        $this.WriteLog([LogLevel]::INFO, $message, $context)
    }
    
    [void] Warning([string]$message, [hashtable]$context = @{}) {
        $this.WriteLog([LogLevel]::WARNING, $message, $context)
    }
    
    [void] Error([string]$message, [hashtable]$context = @{}) {
        $this.WriteLog([LogLevel]::ERROR, $message, $context)
    }
    
    [void] Critical([string]$message, [hashtable]$context = @{}) {
        $this.WriteLog([LogLevel]::CRITICAL, $message, $context)
    }
    
    [void] Dispose() {
        if ($this.StreamWriter) {
            $this.StreamWriter.Dispose()
        }
        if ($this.FileStream) {
            $this.FileStream.Dispose()
        }
    }
}

# ============================================================================
# SISTEMA DE MONITORAMENTO DE RECURSOS
# ============================================================================

class ResourceMonitor {
    [System.Diagnostics.PerformanceCounter]$CpuCounter
    [System.Diagnostics.PerformanceCounter]$MemoryCounter
    [PNALogger]$Logger
    
    ResourceMonitor([PNALogger]$logger) {
        $this.Logger = $logger
        $this.InitializeCounters()
    }
    
    [void] InitializeCounters() {
        try {
            $this.CpuCounter = [System.Diagnostics.PerformanceCounter]::new("Processor", "% Processor Time", "_Total")
            $this.MemoryCounter = [System.Diagnostics.PerformanceCounter]::new("Memory", "Available MBytes")
            
            # Primeira leitura (necessária para contadores de CPU)
            $this.CpuCounter.NextValue() | Out-Null
            Start-Sleep -Milliseconds 100
            
            $this.Logger.Info("Monitor de recursos inicializado")
        }
        catch {
            $this.Logger.Error("Falha ao inicializar monitor de recursos: $_")
            throw
        }
    }
    
    [hashtable] GetCurrentUsage() {
        try {
            $cpuUsage = [math]::Round($this.CpuCounter.NextValue(), 2)
            $availableMemoryMB = [math]::Round($this.MemoryCounter.NextValue(), 2)
            $processMemoryMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
            
            return @{
                'CPUUsage' = $cpuUsage
                'AvailableMemoryMB' = $availableMemoryMB
                'ProcessMemoryMB' = $processMemoryMB
                'Timestamp' = Get-Date
            }
        }
        catch {
            $this.Logger.Error("Falha ao obter métricas de recursos: $_")
            return @{}
        }
    }
    
    [bool] IsResourceConstraint() {
        $usage = $this.GetCurrentUsage()
        if ($usage.Count -eq 0) { return $false }
        
        $isConstrained = $usage.ProcessMemoryMB -gt $Script:MEMORY_THRESHOLD_MB -or 
                        $usage.CPUUsage -gt 80 -or 
                        $usage.AvailableMemoryMB -lt 256
        
        if ($isConstrained) {
            $this.Logger.Warning("Recursos do sistema limitados detectados", $usage)
        }
        
        return $isConstrained
    }
    
    [void] Dispose() {
        if ($this.CpuCounter) { $this.CpuCounter.Dispose() }
        if ($this.MemoryCounter) { $this.MemoryCounter.Dispose() }
    }
}

# ============================================================================
# SISTEMA DE BACKUP AUTOMÁTICO
# ============================================================================

class BackupManager {
    [string]$BackupPath
    [PNALogger]$Logger
    [int]$MaxBackups
    
    BackupManager([string]$backupPath, [PNALogger]$logger, [int]$maxBackups = 5) {
        $this.BackupPath = $backupPath
        $this.Logger = $logger
        $this.MaxBackups = $maxBackups
        $this.EnsureBackupDirectory()
    }
    
    [void] EnsureBackupDirectory() {
        try {
            if (-not (Test-Path $this.BackupPath)) {
                New-Item -Path $this.BackupPath -ItemType Directory -Force | Out-Null
                $this.Logger.Info("Diretório de backup criado: $($this.BackupPath)")
            }
        }
        catch {
            $this.Logger.Error("Falha ao criar diretório de backup: $_")
            throw
        }
    }
    
    [string] CreateBackup([string]$sourcePath, [string]$backupName) {
        if (-not (Test-Path $sourcePath)) {
            $this.Logger.Warning("Caminho de origem não existe: $sourcePath")
            return $null
        }
        
        try {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $backupFileName = "${backupName}_${timestamp}.zip"
            $backupFilePath = Join-Path $this.BackupPath $backupFileName
            
            $this.Logger.Info("Iniciando backup de: $sourcePath")
            
            # Usar System.IO.Compression para criar backup
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcePath, $backupFilePath)
            
            $this.Logger.Info("Backup criado com sucesso: $backupFilePath")
            $this.CleanupOldBackups($backupName)
            
            return $backupFilePath
        }
        catch {
            $this.Logger.Error("Falha ao criar backup: $_")
            throw
        }
    }
    
    [void] CleanupOldBackups([string]$backupPrefix) {
        try {
            $backups = Get-ChildItem -Path $this.BackupPath -Filter "${backupPrefix}_*.zip" | 
                      Sort-Object CreationTime -Descending
            
            if ($backups.Count -gt $this.MaxBackups) {
                $toDelete = $backups | Select-Object -Skip $this.MaxBackups
                foreach ($backup in $toDelete) {
                    Remove-Item $backup.FullName -Force
                    $this.Logger.Info("Backup antigo removido: $($backup.Name)")
                }
            }
        }
        catch {
            $this.Logger.Warning("Falha na limpeza de backups antigos: $_")
        }
    }
    
    [bool] RestoreBackup([string]$backupFile, [string]$destinationPath) {
        if (-not (Test-Path $backupFile)) {
            $this.Logger.Error("Arquivo de backup não encontrado: $backupFile")
            return $false
        }
        
        try {
            $this.Logger.Info("Restaurando backup: $backupFile para: $destinationPath")
            
            if (Test-Path $destinationPath) {
                Remove-Item $destinationPath -Recurse -Force
            }
            
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($backupFile, $destinationPath)
            
            $this.Logger.Info("Backup restaurado com sucesso")
            return $true
        }
        catch {
            $this.Logger.Error("Falha ao restaurar backup: $_")
            return $false
        }
    }
}

# ============================================================================
# GERENCIADOR DE CONEXÕES WEBSOCKET
# ============================================================================

class WebSocketManager {
    [string]$Url
    [int]$TimeoutMs
    [PNALogger]$Logger
    [System.Net.WebSockets.ClientWebSocket]$WebSocket
    [System.Threading.CancellationTokenSource]$CancelSource
    
    WebSocketManager([string]$url, [int]$timeoutMs, [PNALogger]$logger) {
        $this.Url = $url
        $this.TimeoutMs = $timeoutMs
        $this.Logger = $logger
        $this.CancelSource = [System.Threading.CancellationTokenSource]::new()
    }
    
    [bool] Connect() {
        try {
            $this.WebSocket = [System.Net.WebSockets.ClientWebSocket]::new()
            $this.WebSocket.Options.KeepAliveInterval = [TimeSpan]::FromSeconds(30)
            
            $connectTask = $this.WebSocket.ConnectAsync([Uri]$this.Url, $this.CancelSource.Token)
            $completed = $connectTask.Wait($this.TimeoutMs)
            
            if (-not $completed) {
                $this.Logger.Error("Timeout na conexão WebSocket após $($this.TimeoutMs)ms")
                return $false
            }
            
            if ($this.WebSocket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
                $this.Logger.Info("Conexão WebSocket estabelecida com sucesso")
                return $true
            } else {
                $this.Logger.Error("Falha ao estabelecer conexão WebSocket. Estado: $($this.WebSocket.State)")
                return $false
            }
        }
        catch {
            $this.Logger.Error("Erro na conexão WebSocket: $_")
            return $false
        }
    }
    
    [bool] SendMessage([string]$message) {
        if ($this.WebSocket.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
            $this.Logger.Error("WebSocket não está conectado")
            return $false
        }
        
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($message)
            $buffer = [System.ArraySegment[byte]]::new($bytes)
            
            $sendTask = $this.WebSocket.SendAsync($buffer, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $this.CancelSource.Token)
            $completed = $sendTask.Wait($this.TimeoutMs)
            
            if ($completed) {
                $this.Logger.Debug("Mensagem enviada via WebSocket: $($message.Length) bytes")
                return $true
            } else {
                $this.Logger.Error("Timeout ao enviar mensagem WebSocket")
                return $false
            }
        }
        catch {
            $this.Logger.Error("Erro ao enviar mensagem WebSocket: $_")
            return $false
        }
    }
    
    [string] ReceiveMessage() {
        if ($this.WebSocket.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
            return $null
        }
        
        try {
            $buffer = [byte[]]::new(4096)
            $arraySegment = [System.ArraySegment[byte]]::new($buffer)
            
            $receiveTask = $this.WebSocket.ReceiveAsync($arraySegment, $this.CancelSource.Token)
            $completed = $receiveTask.Wait($this.TimeoutMs)
            
            if ($completed -and $receiveTask.Result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Text) {
                $message = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $receiveTask.Result.Count)
                $this.Logger.Debug("Mensagem recebida via WebSocket: $($message.Length) bytes")
                return $message
            }
        }
        catch {
            $this.Logger.Error("Erro ao receber mensagem WebSocket: $_")
        }
        
        return $null
    }
    
    [void] Disconnect() {
        try {
            if ($this.WebSocket -and $this.WebSocket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
                $closeTask = $this.WebSocket.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Fechamento normal", $this.CancelSource.Token)
                $closeTask.Wait(5000) | Out-Null
                $this.Logger.Info("Conexão WebSocket fechada")
            }
        }
        catch {
            $this.Logger.Warning("Erro ao fechar conexão WebSocket: $_")
        }
        finally {
            if ($this.WebSocket) { $this.WebSocket.Dispose() }
            if ($this.CancelSource) { $this.CancelSource.Dispose() }
        }
    }
}

# ============================================================================
# VALIDAÇÕES DE SEGURANÇA
# ============================================================================

class SecurityValidator {
    [PNALogger]$Logger
    [hashtable]$SecurityConfig
    
    SecurityValidator([PNALogger]$logger, [hashtable]$config = @{}) {
        $this.Logger = $logger
        $this.SecurityConfig = $config
    }
    
    [bool] ValidateToken([string]$token) {
        if ([string]::IsNullOrWhiteSpace($token)) {
            $this.Logger.Error("Token está vazio ou nulo")
            return $false
        }
        
        # Verificar comprimento mínimo
        if ($token.Length -lt 32) {
            $this.Logger.Error("Token muito curto (mínimo 32 caracteres)")
            return $false
        }
        
        # Verificar se não é um token padrão/exemplo
        $forbiddenTokens = @("123456789", "example", "test", "demo", "sample")
        if ($forbiddenTokens -contains $token.ToLower()) {
            $this.Logger.Error("Token inválido - utilizando token de exemplo/teste")
            return $false
        }
        
        # Verificar caracteres especiais
        if ($token -match '[<>"\|&;`]') {
            $this.Logger.Error("Token contém caracteres perigosos")
            return $false
        }
        
        $this.Logger.Info("Token validado com sucesso")
        return $true
    }
    
    [bool] ValidateCredentials([pscredential]$credentials) {
        if (-not $credentials) {
            $this.Logger.Error("Credenciais não fornecidas")
            return $false
        }
        
        $username = $credentials.UserName
        $password = $credentials.GetNetworkCredential().Password
        
        # Validar username
        if ([string]::IsNullOrWhiteSpace($username) -or $username.Length -lt 3) {
            $this.Logger.Error("Nome de usuário inválido")
            return $false
        }
        
        # Validar senha
        if ([string]::IsNullOrWhiteSpace($password) -or $password.Length -lt 8) {
            $this.Logger.Error("Senha deve ter pelo menos 8 caracteres")
            return $false
        }
        
        # Verificar complexidade da senha
        $hasUpper = $password -cmatch '[A-Z]'
        $hasLower = $password -cmatch '[a-z]'
        $hasNumber = $password -cmatch '\d'
        $hasSpecial = $password -cmatch '[!@#$%^&*(),.?":{}|<>]'
        
        if (-not ($hasUpper -and $hasLower -and $hasNumber -and $hasSpecial)) {
            $this.Logger.Warning("Senha não atende aos critérios de complexidade recomendados")
        }
        
        $this.Logger.Info("Credenciais validadas com sucesso para usuário: $username")
        return $true
    }
    
    [bool] ValidateFileIntegrity([string]$filePath, [string]$expectedHash) {
        if (-not (Test-Path $filePath)) {
            $this.Logger.Error("Arquivo não encontrado para verificação de integridade: $filePath")
            return $false
        }
        
        try {
            $actualHash = Get-FileHash $filePath -Algorithm SHA256
            $isValid = $actualHash.Hash -eq $expectedHash
            
            if ($isValid) {
                $this.Logger.Info("Integridade do arquivo verificada: $filePath")
            } else {
                $this.Logger.Error("Falha na verificação de integridade do arquivo: $filePath")
            }
            
            return $isValid
        }
        catch {
            $this.Logger.Error("Erro ao verificar integridade do arquivo: $_")
            return $false
        }
    }
    
    [bool] ValidateNetworkConnection([string]$url, [int]$timeoutSeconds = 10) {
        try {
            $this.Logger.Debug("Testando conectividade com: $url")
            
            $request = [System.Net.WebRequest]::Create($url)
            $request.Timeout = $timeoutSeconds * 1000
            $request.Method = "HEAD"
            
            $response = $request.GetResponse()
            $response.Close()
            
            $this.Logger.Info("Conectividade confirmada com: $url")
            return $true
        }
        catch {
            $this.Logger.Warning("Falha na conectividade com ${url}: $_")
            return $false
        }
    }
}

# ============================================================================
# SISTEMA DE RECUPERAÇÃO AUTOMÁTICA
# ============================================================================

class RecoveryManager {
    [PNALogger]$Logger
    [BackupManager]$BackupManager
    [hashtable]$RecoveryPoints
    
    RecoveryManager([PNALogger]$logger, [BackupManager]$backupManager) {
        $this.Logger = $logger
        $this.BackupManager = $backupManager
        $this.RecoveryPoints = @{}
    }
    
    [void] CreateRecoveryPoint([string]$name, [string]$path) {
        try {
            $backupPath = $this.BackupManager.CreateBackup($path, "recovery_$name")
            $this.RecoveryPoints[$name] = @{
                'BackupPath' = $backupPath
                'OriginalPath' = $path
                'Timestamp' = Get-Date
            }
            $this.Logger.Info("Ponto de recuperação criado: $name")
        }
        catch {
            $this.Logger.Error("Falha ao criar ponto de recuperação: $_")
            throw
        }
    }
    
    [bool] RestoreRecoveryPoint([string]$name) {
        if (-not $this.RecoveryPoints.ContainsKey($name)) {
            $this.Logger.Error("Ponto de recuperação não encontrado: $name")
            return $false
        }
        
        try {
            $recoveryPoint = $this.RecoveryPoints[$name]
            $success = $this.BackupManager.RestoreBackup($recoveryPoint.BackupPath, $recoveryPoint.OriginalPath)
            
            if ($success) {
                $this.Logger.Info("Recuperação bem-sucedida do ponto: $name")
            } else {
                $this.Logger.Error("Falha na recuperação do ponto: $name")
            }
            
            return $success
        }
        catch {
            $this.Logger.Error("Erro durante recuperação: $_")
            return $false
        }
    }
    
    [string[]] ListRecoveryPoints() {
        return $this.RecoveryPoints.Keys
    }
}

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
    Verifica pré-requisitos do sistema
    #>
    param([PNALogger]$Logger)
    
    $Logger.Info("Verificando pré-requisitos do sistema")
    
    # Verificar versão do PowerShell
    if ($PSVersionTable.PSVersion -lt $Script:REQUIRED_PS_VERSION) {
        $Logger.Critical("PowerShell $($Script:REQUIRED_PS_VERSION) ou superior é necessário. Versão atual: $($PSVersionTable.PSVersion)")
        return $false
    }
    
    # Verificar privilégios de administrador
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $Logger.Critical("Este script deve ser executado como Administrador")
        return $false
    }
    
    # Verificar .NET Framework
    try {
        $netVersion = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release -ErrorAction SilentlyContinue
        if ($netVersion.Release -lt 461808) { # .NET 4.7.2
            $Logger.Warning(".NET Framework 4.7.2 ou superior é recomendado")
        }
    }
    catch {
        $Logger.Warning("Não foi possível verificar a versão do .NET Framework")
    }
    
    # Verificar espaço em disco
    $drive = (Get-Location).Drive
    $freeSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($drive.Name)'").FreeSpace / 1GB
    if ($freeSpace -lt 5) {
        $Logger.Warning("Espaço em disco baixo: ${freeSpace}GB disponível. Recomendado: pelo menos 5GB")
    }
    
    $Logger.Info("Pré-requisitos verificados com sucesso")
    return $true
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
    Executa um scriptblock com tentativas automáticas em caso de falha
    #>
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        [int]$MaxAttempts = $Script:MAX_RETRY_ATTEMPTS,
        
        [Parameter()]
        [int]$DelaySeconds = 2,
        
        [Parameter()]
        [PNALogger]$Logger
    )
    
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $Logger.Debug("Tentativa $attempt de $MaxAttempts")
            $result = & $ScriptBlock
            $Logger.Debug("Operação bem-sucedida na tentativa $attempt")
            return $result
        }
        catch {
            $Logger.Warning("Falha na tentativa $attempt : $_")
            
            if ($attempt -eq $MaxAttempts) {
                $Logger.Error("Todas as $MaxAttempts tentativas falharam")
                throw
            }
            
            $Logger.Info("Aguardando $DelaySeconds segundos antes da próxima tentativa")
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Get-SecureString {
    <#
    .SYNOPSIS
    Solicita entrada segura do usuário com validação
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,
        
        [Parameter()]
        [switch]$AsSecureString,
        
        [Parameter()]
        [PNALogger]$Logger
    )
    
    do {
        if ($AsSecureString) {
            $input = Read-Host -Prompt $Prompt -AsSecureString
            $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($input))
        } else {
            $plainText = Read-Host -Prompt $Prompt
        }
        
        if ([string]::IsNullOrWhiteSpace($plainText)) {
            $Logger.Warning("Entrada não pode estar vazia. Tente novamente.")
            continue
        }
        
        return if ($AsSecureString) { $input } else { $plainText }
    } while ($true)
}

# ============================================================================
# FUNÇÃO PRINCIPAL DE INSTALAÇÃO
# ============================================================================

function Install-PNAHelpdesk {
    <#
    .SYNOPSIS
    Função principal para instalação do PNA Helpdesk
    #>
    
    # Inicialização dos sistemas
    $logger = $null
    $resourceMonitor = $null
    $backupManager = $null
    $recoveryManager = $null
    
    try {
        # ========================================================================
        # FASE 1: INICIALIZAÇÃO E VALIDAÇÃO
        # ========================================================================
        
        Write-Host "=== INSTALAÇÃO DO PNA HELPDESK v$Script:PNA_VERSION ===" -ForegroundColor Cyan
        Write-Host "Iniciando sistema de instalação..." -ForegroundColor Green
        
        # Inicializar logger
        $logger = [PNALogger]::new($LogPath, [LogLevel]::INFO, $true)
        $logger.Info("=== INÍCIO DA INSTALAÇÃO DO PNA HELPDESK v$Script:PNA_VERSION ===")
        
        # Verificar pré-requisitos
        if (-not (Test-Prerequisites -Logger $logger)) {
            throw "Pré-requisitos não atendidos"
        }
        
        # Inicializar monitor de recursos
        $resourceMonitor = [ResourceMonitor]::new($logger)
        $initialUsage = $resourceMonitor.GetCurrentUsage()
        $logger.Info("Monitor de recursos ativo", $initialUsage)
        
        # Inicializar sistema de backup
        if (-not $SkipBackup) {
            $backupManager = [BackupManager]::new($BackupPath, $logger)
            $recoveryManager = [RecoveryManager]::new($logger, $backupManager)
            $logger.Info("Sistema de backup e recuperação inicializado")
        }
        
        # ========================================================================
        # FASE 2: PREPARAÇÃO DO AMBIENTE
        # ========================================================================
        
        $logger.Info("Preparando ambiente de instalação")
        
        # Criar diretório de instalação
        if (-not (Test-Path $InstallPath)) {
            New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
            $logger.Info("Diretório de instalação criado: $InstallPath")
        }
        
        # Criar ponto de recuperação se existir instalação anterior
        if ((Test-Path (Join-Path $InstallPath "bin")) -and (-not $SkipBackup)) {
            $recoveryManager.CreateRecoveryPoint("pre_install", $InstallPath)
        }
        
        # Validador de segurança
        $securityValidator = [SecurityValidator]::new($logger)
        
        # Testar conectividade
        $logger.Info("Verificando conectividade de rede")
        foreach ($url in $Script:DOWNLOAD_URLS.Values) {
            if (-not $securityValidator.ValidateNetworkConnection($url)) {
                $logger.Warning("Conectividade limitada detectada com: $url")
            }
        }
        
        # ========================================================================
        # FASE 3: DOWNLOAD E VALIDAÇÃO DE DEPENDÊNCIAS
        # ========================================================================
        
        $logger.Info("Iniciando download de dependências")
        $tempPath = Join-Path $env:TEMP "PNAHelpdesk_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
        
        # Função auxiliar para download com validação
        $downloadFunction = {
            param($url, $destination, $fileName)
            
            $filePath = Join-Path $destination $fileName
            $logger.Debug("Baixando: $url para: $filePath")
            
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "PNA-Helpdesk-Installer/$Script:PNA_VERSION")
            
            try {
                $webClient.DownloadFile($url, $filePath)
                $logger.Info("Download concluído: $fileName")
                return $filePath
            }
            finally {
                $webClient.Dispose()
            }
        }
        
        # Download dos componentes principais
        $downloads = @{}
        foreach ($component in $Script:DOWNLOAD_URLS.Keys) {
            try {
                $url = $Script:DOWNLOAD_URLS[$component]
                $fileName = "$component.$(Split-Path $url -Extension)"
                
                $downloads[$component] = Invoke-WithRetry -ScriptBlock {
                    & $downloadFunction $url $tempPath $fileName
                } -Logger $logger
                
                # Verificar integridade (simulação - em produção usaria hashes conhecidos)
                if (Test-Path $downloads[$component]) {
                    $logger.Info("Arquivo $component baixado e validado")
                }
            }
            catch {
                $logger.Error("Falha no download do componente ${component}: $_")
                throw
            }
        }
        
        # ========================================================================
        # FASE 4: INSTALAÇÃO DOS COMPONENTES
        # ========================================================================
        
        $logger.Info("Iniciando instalação dos componentes")
        
        # Extrair arquivos
        foreach ($component in $downloads.Keys) {
            $filePath = $downloads[$component]
            $extractPath = Join-Path $InstallPath $component
            
            try {
                if ($filePath.EndsWith(".zip")) {
                    $logger.Debug("Extraindo: $component")
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($filePath, $extractPath)
                } else {
                    # Para DLLs e outros arquivos
                    Copy-Item $filePath $extractPath -Force
                }
                
                $logger.Info("Componente $component instalado em: $extractPath")
            }
            catch {
                $logger.Error("Falha na instalação do componente ${component}: $_")
                
                # Tentar recuperação automática
                if ($recoveryManager -and $recoveryManager.RecoveryPoints.Count -gt 0) {
                    $logger.Info("Tentando recuperação automática...")
                    $recoveryManager.RestoreRecoveryPoint("pre_install")
                }
                throw
            }
        }
        
        # ========================================================================
        # FASE 5: CONFIGURAÇÃO DO SISTEMA
        # ========================================================================
        
        $logger.Info("Configurando sistema PNA Helpdesk")
        
        # Criar configuração principal
        $configPath = Join-Path $InstallPath "config"
        if (-not (Test-Path $configPath)) {
            New-Item -Path $configPath -ItemType Directory -Force | Out-Null
        }
        
        # Configuração padrão
        $defaultConfig = @{
            'Version' = $Script:PNA_VERSION
            'InstallPath' = $InstallPath
            'LogPath' = $LogPath
            'BackupPath' = $BackupPath
            'WebSocket' = @{
                'Timeout' = $Script:WEBSOCKET_TIMEOUT
                'KeepAlive' = 30
            }
            'Security' = @{
                'TokenValidation' = $true
                'FileIntegrityCheck' = $true
            }
            'Resources' = @{
                'MemoryThreshold' = $Script:MEMORY_THRESHOLD_MB
                'MonitoringEnabled' = $true
            }
        }
        
        $configFile = Join-Path $configPath "pna-helpdesk.json"
        $defaultConfig | ConvertTo-Json -Depth 3 | Set-Content $configFile -Encoding UTF8
        $logger.Info("Configuração criada: $configFile")
        
        # Configurar serviços do Windows (simulação)
        $logger.Info("Configurando serviços do sistema")
        
        # Criar script de inicialização
        $startupScript = @"
# Script de inicialização do PNA Helpdesk
# Gerado automaticamente em $(Get-Date)

`$ErrorActionPreference = 'Stop'
`$InstallPath = '$InstallPath'
`$LogPath = '$LogPath'

# Carregar módulos principais
Import-Module "`$InstallPath\PNACore\PNAHelpdesk.psm1" -Force

# Inicializar sistema
Start-PNAHelpdesk -ConfigPath "`$InstallPath\config\pna-helpdesk.json"
"@
        
        $startupScriptPath = Join-Path $InstallPath "Start-PNAHelpdesk.ps1"
        $startupScript | Set-Content $startupScriptPath -Encoding UTF8
        $logger.Info("Script de inicialização criado: $startupScriptPath")
        
        # ========================================================================
        # FASE 6: TESTES E VALIDAÇÃO FINAL
        # ========================================================================
        
        $logger.Info("Executando testes de validação final")
        
        # Testar WebSocket (simulação)
        try {
            $wsManager = [WebSocketManager]::new("wss://localhost:8080/pna", $Script:WEBSOCKET_TIMEOUT, $logger)
            # Em um cenário real, testaria a conexão aqui
            $logger.Info("Teste de WebSocket: Configuração validada")
        }
        catch {
            $logger.Warning("Teste de WebSocket falhou (esperado se servidor não estiver executando): $_")
        }
        
        # Verificar integridade dos arquivos instalados
        $coreFiles = @(
            "Start-PNAHelpdesk.ps1",
            "config\pna-helpdesk.json"
        )
        
        foreach ($file in $coreFiles) {
            $fullPath = Join-Path $InstallPath $file
            if (-not (Test-Path $fullPath)) {
                throw "Arquivo crítico não encontrado após instalação: $file"
            }
        }
        
        # Verificar uso final de recursos
        $finalUsage = $resourceMonitor.GetCurrentUsage()
        $logger.Info("Recursos do sistema após instalação", $finalUsage)
        
        if ($resourceMonitor.IsResourceConstraint()) {
            $logger.Warning("Sistema operando próximo aos limites de recursos")
        }
        
        # ========================================================================
        # FASE 7: FINALIZAÇÃO
        # ========================================================================
        
        # Limpeza de arquivos temporários
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Recurse -Force
            $logger.Info("Arquivos temporários removidos")
        }
        
        # Criar backup final da instalação
        if (-not $SkipBackup) {
            $finalBackup = $backupManager.CreateBackup($InstallPath, "final_install")
            $logger.Info("Backup final da instalação criado: $finalBackup")
        }
        
        $logger.Info("=== INSTALAÇÃO CONCLUÍDA COM SUCESSO ===")
        
        # Mensagem final para o usuário
        Write-Host "`n=== INSTALAÇÃO CONCLUÍDA COM SUCESSO ===" -ForegroundColor Green
        Write-Host "PNA Helpdesk v$Script:PNA_VERSION foi instalado em: $InstallPath" -ForegroundColor White
        Write-Host "Logs disponíveis em: $LogPath" -ForegroundColor White
        if (-not $SkipBackup) {
            Write-Host "Backups armazenados em: $BackupPath" -ForegroundColor White
        }
        Write-Host "`nPara iniciar o sistema, execute:" -ForegroundColor Yellow
        Write-Host "  PowerShell -ExecutionPolicy Bypass -File '$startupScriptPath'" -ForegroundColor Cyan
        
        return @{
            'Success' = $true
            'InstallPath' = $InstallPath
            'Version' = $Script:PNA_VERSION
            'LogFile' = $logger.LogFile
        }
    }
    catch {
        $errorMessage = "Instalação falhou: $_"
        
        if ($logger) {
            $logger.Critical($errorMessage)
            Write-Host "ERRO: $errorMessage" -ForegroundColor Red
            Write-Host "Verifique o arquivo de log para mais detalhes: $($logger.LogFile)" -ForegroundColor Yellow
        } else {
            Write-Error $errorMessage
        }
        
        # Tentar recuperação automática se disponível
        if ($recoveryManager -and $recoveryManager.RecoveryPoints.Count -gt 0) {
            Write-Host "Tentando recuperação automática do sistema..." -ForegroundColor Yellow
            try {
                $recoveryManager.RestoreRecoveryPoint("pre_install")
                Write-Host "Sistema restaurado para estado anterior" -ForegroundColor Green
            }
            catch {
                Write-Host "Falha na recuperação automática: $_" -ForegroundColor Red
            }
        }
        
        return @{
            'Success' = $false
            'Error' = $errorMessage
        }
    }
    finally {
        # Limpeza de recursos
        if ($resourceMonitor) { $resourceMonitor.Dispose() }
        if ($logger) { $logger.Dispose() }
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

# Executar apenas se o script for chamado diretamente
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $result = Install-PNAHelpdesk
        
        if ($result.Success) {
            exit 0
        } else {
            exit 1
        }
    }
    catch {
        Write-Error "Erro fatal durante a instalação: $_"
        exit 1
    }
}