// Author: AJ
// Date: 2024-12-24
// Last modified: 2024-12-24

// Пример вируса, использующего строку "ThisProgramIsInfected" (для примера) или хеш-сигнатуру.
rule VirusExample
{
    meta:
        description = "Detects a known virus pattern"
        author = "AJ"
        date = "2024-12-24"
        last_modified = "2024-12-24"

    strings:
        $a = "ThisProgramIsInfected"  // Example signature in the virus
        $b = { E8 ?? ?? ?? ?? 83 C4 04 }  // Hexadecimal signature of the virus

    condition:
        $a or $b
}

// Это правило, ориентированное на JavaScript-код
rule MaliciousJS
{
    meta:
        description = "Detects potentially malicious JavaScript"
        author = "AJ"
        date = "2024-12-24"
        last_modified = "2024-12-24"

    strings:
        $js_start = /<script[^>]*>/
        $js_end = /<\/script>/
        $suspicious_code = /eval\(/  // Suspicious use of eval()

    condition:
        $js_start and $js_end and $suspicious_code
}

// Пример трояна, который может быть скомпилирован под разные платформы.
// "This file is a trojan" - сигнатура для примера
rule TrojanDetection
{
    meta:
        description = "Detects trojan using partial signature and file pattern"
        author = "AJ"
        date = "2024-12-24"
        last_modified = "2024-12-24"

    strings:
        $s1 = "This file is a trojan"  // Simple string signature
        $s2 = { 4D 5A 90 00 03 00 00 00 }  // MZ header of a Windows executable

    condition:
        $s1 or $s2
}

// Это правило теперь ищет архивы с возможными исполнимыми файлами, такими как .sh (скрипты для Linux)
rule DangerousArchive
{
    meta:
        description = "Detects archives with potential harmful content (e.g., TAR files with executable)"
        author = "AJ"
        date = "2024-12-24"
        last_modified = "2024-12-24"

    strings:
        $exe_signature = ".sh"  // Looking for shell scripts or executable in Linux archive
        $tar_signature = "7573746172"  // Header for TAR files (ASCII for 'ustar')

    condition:
        $tar_signature and $exe_signature
}

// Это правило проверяет операции с критическими системными файлами, такими как /bin/bash.
rule FileOperationVirus
{
    meta:
        description = "Detects malware that tries to overwrite critical system files"
        author = "AJ"
        date = "2024-12-24"
        last_modified = "2024-12-24"

    strings:
        $critical_file = "/bin/bash"  // Critical system file (example for Linux)
        $file_operation = "open"  // Open system file, often used by malware for manipulation

    condition:
        $critical_file and $file_operation
}
