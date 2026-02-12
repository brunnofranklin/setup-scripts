# PNA Helpdesk - Script de Instalação PowerShell

## Visão Geral

O **PNA Helpdesk** é um sistema robusto de helpdesk com recursos avançados de segurança, monitoramento e recuperação automática. Este script de instalação PowerShell implementa todas as melhores práticas modernas para garantir uma instalação segura e confiável.

## Características Principais

### 🔒 **Segurança Avançada**
- Validação robusta de tokens e credenciais
- Verificação de integridade de arquivos com SHA256
- Validações de conectividade de rede com timeout configurável
- Proteção contra caracteres maliciosos em entradas

### 📊 **Sistema de Logging Detalhado**
- Múltiplos níveis de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Logs estruturados com timestamp, PID, TID e contexto
- Suporte a logging assíncrono e thread-safe
- Rotação automática de logs

### 🔄 **Backup e Recuperação Automática**
- Sistema de backup automático com compressão
- Pontos de recuperação com rollback automático
- Limpeza automática de backups antigos
- Validação de integridade dos backups

### 📈 **Monitoramento de Recursos**
- Monitoramento em tempo real de CPU, memória e disco
- Detecção automática de restrições de recursos
- Alertas proativos para uso excessivo de recursos
- Otimização automática de memória

### 🌐 **Gerenciamento Otimizado de WebSocket**
- Conexões WebSocket com timeout configurável
- Keep-alive automático para manter conexões estáveis
- Buffer otimizado para performance
- Tratamento robusto de erros de conectividade

### 🛠 **Sistema de Recuperação Inteligente**
- Recuperação automática em caso de falha na instalação
- Múltiplos pontos de recuperação
- Rollback automático para estado anterior
- Validação pós-recuperação

## Requisitos do Sistema

### Pré-requisitos Obrigatórios
- **PowerShell**: 5.1 ou superior
- **Sistema Operacional**: Windows 10, Windows Server 2016/2019/2022
- **.NET Framework**: 4.7.2 ou superior
- **Privilégios**: Execução como Administrador
- **Espaço em Disco**: Mínimo 5GB livres
- **Memória RAM**: Mínimo 2GB disponível

### Conectividade de Rede
- Acesso HTTPS para download de dependências
- Suporte a WebSocket (WSS) para funcionalidades avançadas
- Conectividade com os servidores de distribuição PNA

## Instalação

### Instalação Básica

```powershell
# Executar como Administrador
.\Install-PNAHelpdesk.ps1
```

### Instalação Personalizada

```powershell
# Instalação com parâmetros personalizados
.\Install-PNAHelpdesk.ps1 `
    -InstallPath "D:\PNAHelpdesk" `
    -LogPath "D:\Logs\PNAHelpdesk" `
    -BackupPath "D:\Backup\PNAHelpdesk" `
    -Verbose
```

### Instalação sem Backup

```powershell
# Para ambientes de teste (não recomendado para produção)
.\Install-PNAHelpdesk.ps1 -SkipBackup
```

## Parâmetros de Configuração

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `InstallPath` | String | `C:\PNAHelpdesk` | Diretório de instalação |
| `LogPath` | String | `C:\PNAHelpdesk\Logs` | Diretório para logs |
| `BackupPath` | String | `C:\PNAHelpdesk\Backup` | Diretório para backups |
| `ConfigFile` | String | (Opcional) | Arquivo de configuração personalizado |
| `SkipBackup` | Switch | `$false` | Pula criação de backups |

## Estrutura de Arquivos Pós-Instalação

```
C:\PNAHelpdesk\
├── bin/                          # Executáveis principais
├── config/
│   └── pna-helpdesk.json        # Configuração principal
├── logs/
│   └── PNAHelpdesk_*.log        # Logs do sistema
├── backup/
│   └── *.zip                    # Backups automáticos
├── PNACore/                     # Módulos principais
├── Dependencies/                # Dependências
├── WebSocketLib/               # Biblioteca WebSocket
├── AuthModule/                 # Módulo de autenticação
└── Start-PNAHelpdesk.ps1       # Script de inicialização
```

## Sistema de Logging

### Níveis de Log
- **DEBUG**: Informações detalhadas para desenvolvimento
- **INFO**: Informações gerais de operação
- **WARNING**: Avisos que não impedem a operação
- **ERROR**: Erros que podem afetar funcionalidades
- **CRITICAL**: Erros críticos que impedem a operação

### Formato de Log
```
[2024-01-15 14:30:25.123] [INFO    ] [1234:5678] Mensagem do log | Context: {"key":"value"}
```

### Configuração de Logs
```json
{
  "Logging": {
    "DefaultLevel": "INFO",
    "WriteToConsole": true,
    "WriteToFile": true,
    "MaxLogFileSize": "100MB",
    "MaxLogFiles": 10,
    "LogRotation": "Daily"
  }
}
```

## Sistema de Backup

### Configurações de Backup
- **Backup Automático**: Habilitado por padrão
- **Máximo de Backups**: 5 (configurável)
- **Compressão**: ZIP com nível otimizado
- **Limpeza Automática**: Remove backups antigos automaticamente

### Comandos de Backup Manual
```powershell
# Criar backup manual
$backupManager = [BackupManager]::new("C:\Backups", $logger)
$backupPath = $backupManager.CreateBackup("C:\PNAHelpdesk", "manual_backup")

# Restaurar backup
$success = $backupManager.RestoreBackup($backupPath, "C:\PNAHelpdesk")
```

## Monitoramento de Recursos

### Métricas Monitoradas
- **CPU**: Uso percentual do processador
- **Memória**: Memória disponível e uso do processo
- **Disco**: Espaço livre em disco
- **Rede**: Status de conectividade

### Limites Padrão
- **Memória do Processo**: 512MB
- **CPU**: 80%
- **Memória Disponível**: 256MB
- **Espaço em Disco**: 5GB

### Configuração de Monitoramento
```json
{
  "ResourceMonitoring": {
    "Enabled": true,
    "MemoryThreshold": 512,
    "CpuThreshold": 80,
    "DiskThreshold": 5,
    "MonitoringInterval": 60
  }
}
```

## Segurança e Validações

### Validação de Tokens
- **Comprimento Mínimo**: 32 caracteres
- **Tokens Proibidos**: Lista de tokens inseguros bloqueados
- **Caracteres Perigosos**: Bloqueio de caracteres que podem ser explorados

### Política de Senhas
- **Comprimento Mínimo**: 8 caracteres
- **Complexidade**: Maiúsculas, minúsculas, números e símbolos
- **Validação**: Verificação automática de critérios de segurança

### Verificação de Integridade
- **Algoritmo**: SHA256
- **Verificação**: Automática durante instalação
- **Validação**: Contínua para arquivos críticos

## WebSocket e Conectividade

### Configurações WebSocket
- **Timeout**: 30 segundos (configurável)
- **Keep-Alive**: 30 segundos
- **Buffer**: 4KB (otimizado)
- **Protocolo**: WSS (WebSocket Secure)

### Exemplo de Conexão WebSocket
```powershell
$wsManager = [WebSocketManager]::new("wss://servidor.pna.com/helpdesk", 30000, $logger)
$connected = $wsManager.Connect()

if ($connected) {
    $wsManager.SendMessage("Mensagem de teste")
    $response = $wsManager.ReceiveMessage()
    $wsManager.Disconnect()
}
```

## Sistema de Recuperação

### Pontos de Recuperação Automáticos
- **Pré-instalação**: Antes de qualquer modificação
- **Pós-componente**: Após instalação de cada componente
- **Configuração**: Após alterações de configuração

### Recuperação Manual
```powershell
# Listar pontos de recuperação
$recoveryManager.ListRecoveryPoints()

# Restaurar ponto específico
$recoveryManager.RestoreRecoveryPoint("pre_install")
```

## Testes e Validação

### Executar Testes
```powershell
# Executar bateria completa de testes
.\Test-PNAHelpdeskInstaller.ps1 -Verbose

# Testes em diretório personalizado
.\Test-PNAHelpdeskInstaller.ps1 -TestPath "D:\Temp\Tests"
```

### Testes Implementados
1. **Sistema de Logging**: Validação completa do sistema de logs
2. **Validações de Segurança**: Testes de tokens, credenciais e integridade
3. **Sistema de Backup**: Criação, restauração e limpeza de backups
4. **Monitor de Recursos**: Coleta e validação de métricas
5. **WebSocket**: Conectividade e comunicação
6. **Sistema de Recuperação**: Pontos de recuperação e rollback
7. **Funções Auxiliares**: Retry, pré-requisitos e utilitários

## Configuração Avançada

### Arquivo de Configuração (pna-helpdesk-config.json)
O sistema suporta configuração via arquivo JSON com as seguintes seções:

- **Application**: Informações da aplicação
- **Installation**: Configurações de instalação  
- **Security**: Políticas de segurança
- **Logging**: Configuração de logs
- **WebSocket**: Parâmetros de WebSocket
- **Backup**: Configurações de backup
- **ResourceMonitoring**: Monitoramento de recursos
- **Recovery**: Sistema de recuperação
- **Dependencies**: Dependências e URLs
- **Performance**: Otimizações de performance
- **Notifications**: Sistema de notificações

### Exemplo de Configuração Personalizada
```json
{
  "Security": {
    "TokenValidation": {
      "MinLength": 64,
      "RequireComplexity": true
    }
  },
  "ResourceMonitoring": {
    "MemoryThreshold": 1024,
    "CpuThreshold": 70
  },
  "WebSocket": {
    "DefaultTimeout": 60000,
    "MaxConnections": 200
  }
}
```

## Solução de Problemas

### Problemas Comuns

#### 1. Erro de Privilégios
**Sintoma**: "Este script deve ser executado como Administrador"
**Solução**: Execute o PowerShell como Administrador

#### 2. Falha na Conectividade
**Sintoma**: Downloads falham ou WebSocket não conecta
**Solução**: Verifique proxy, firewall e conectividade de rede

#### 3. Espaço Insuficiente
**Sintoma**: "Espaço em disco baixo"
**Solução**: Libere espaço em disco ou altere diretório de instalação

#### 4. Falha na Verificação de Integridade
**Sintoma**: "Falha na verificação de integridade do arquivo"
**Solução**: Baixe novamente os arquivos ou verifique conectividade

### Logs de Diagnóstico

#### Localização dos Logs
- **Logs de Instalação**: `%InstallPath%\Logs\PNAHelpdesk_*.log`
- **Logs de Sistema**: Event Viewer → Applications and Services Logs
- **Logs de Teste**: `%TestPath%\TestLogs\`

#### Análise de Logs
```powershell
# Filtrar logs por nível
Get-Content "C:\PNAHelpdesk\Logs\*.log" | Where-Object { $_ -match "\[ERROR\]|\[CRITICAL\]" }

# Logs das últimas 24 horas
Get-Content "C:\PNAHelpdesk\Logs\*.log" | Where-Object { 
    $_ -match "$(Get-Date -Format 'yyyy-MM-dd')" 
}
```

### Recuperação de Emergência

#### Em Caso de Falha Crítica
1. **Parar Serviços**: Pare todos os serviços PNA
2. **Verificar Logs**: Analise logs para identificar causa
3. **Recuperar Backup**: Use o ponto de recuperação mais recente
4. **Validar Sistema**: Execute testes pós-recuperação

```powershell
# Recuperação automática
$recoveryManager = [RecoveryManager]::new($logger, $backupManager)
$recoveryManager.RestoreRecoveryPoint("pre_install")
```

## Suporte e Contato

### Informações de Suporte
- **Documentação**: [docs.pna.com/helpdesk](https://docs.pna.com/helpdesk)
- **Suporte Técnico**: support@pna.com
- **Issues**: [github.com/pna/helpdesk/issues](https://github.com/pna/helpdesk/issues)

### Logs para Suporte
Ao reportar problemas, inclua:
1. Arquivo de log completo da instalação
2. Resultado dos testes (`Test-PNAHelpdeskInstaller.ps1`)
3. Informações do sistema (OS, PowerShell version, .NET version)
4. Configurações personalizadas utilizadas

## Versionamento e Updates

### Versão Atual
- **Versão**: 2.0.1
- **Data de Lançamento**: 2024
- **Compatibilidade**: PowerShell 5.1+, Windows 10+

### Histórico de Versões
- **2.0.1**: Melhorias de segurança e estabilidade
- **2.0.0**: Implementação completa com todos os recursos avançados
- **1.x**: Versões legadas (descontinuadas)

### Atualizações Futuras
- Suporte a PowerShell Core 7+
- Integração com Azure Monitor
- Suporte a containers Docker
- API REST para gerenciamento remoto

## Licença e Conformidade

### Licença
Este software é propriedade da PNA Development Team e está licenciado sob os termos específicos da empresa.

### Conformidade
- **LGPD**: Compatível com Lei Geral de Proteção de Dados
- **Security Standards**: Segue práticas de segurança modernas
- **Audit Trail**: Logs completos para auditoria
- **Backup Requirements**: Atende requisitos de continuidade de negócios

---

**© 2024 PNA Development Team. Todos os direitos reservados.**