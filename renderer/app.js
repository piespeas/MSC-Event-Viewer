const { exec } = require("child_process");
const os = require("os");

// ============================================================================
//                         CONFIGURATION
// ============================================================================

const CHANNEL_LOG_PATHS = {
    "Security": "Security",
    "System": "System",
    "PowerShell": "Microsoft-Windows-PowerShell/Operational",
    "Task Scheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "Windows Defender": "Microsoft-Windows-WindowsDefender/Operational",
    "NTFS": "Microsoft-Windows-Ntfs/Operational",
    "WMI": "Microsoft-Windows-WMI-Activity/Operational",
    "Sysmon": "Microsoft-Windows-Sysmon/Operational",
    "Firewall": "Microsoft-Windows-WindowsFirewallWithAdvancedSecurity/Firewall"
};

const LOG_ID_MESSAGES = {
    // === Security: Logon / Privilege Abuse ===
    "Security_4624": "Successful Account Logon",
    "Security_4625": "Failed logon attempt recorded",
    "Security_4627": "Group membership assigned at logon (Privileges mapped)",
    "Security_4634": "User logoff recorded (Session tracking)",
    "Security_4647": "User initiated logoff",
    "Security_4648": "Explicit credential usage detected (RunAs / Alternate credentials)",
    "Security_4649": "Replay attack vector detected",
    "Security_4672": "Special admin privileges assigned to logon session",
    "Security_4673": "Privileged service called",
    "Security_4674": "Operation attempted on privileged object",
    "Security_4768": "Kerberos TGT requested (Domain Authentication)",
    "Security_4769": "Kerberos service ticket requested (Lateral Movement tracking)",
    "Security_4771": "Kerberos pre-auth failure (Password Attack indicator)",
    "Security_4776": "NTLM authentication interface tracking",
    "Security_4778": "Session reconnected (Remote Access)",
    "Security_4779": "Session disconnected (Remote Access)",

    // === Security: Account Management ===
    "Security_4720": "User account created",
    "Security_4722": "User account enabled",
    "Security_4723": "Password change attempted",
    "Security_4724": "Password reset attempted",
    "Security_4725": "User account disabled",
    "Security_4726": "User account deleted",
    "Security_4738": "User account structurally changed",
    "Security_4740": "Account locked out",

    // === Security: Group Management ===
    "Security_4728": "Added to global security group",
    "Security_4729": "Removed from global security group",
    "Security_4732": "Added to local security group",
    "Security_4733": "Removed from local security group",
    "Security_4756": "Added to universal security group",
    "Security_4757": "Removed from universal security group",

    // === Security: Process & Tampering ===
    "Security_4616": "System time changed (Timestamp manipulation risk)",
    "Security_4688": "Process execution detected (Process Creation)",
    "Security_4689": "Process termination detected",
    "Security_4697": "New service installation detected",
    "Security_4719": "Audit policy changed",
    "Security_1102": "Security audit log cleared!",

    // === Object Access ===
    "Security_4656": "Handle requested to object",
    "Security_4663": "Object accessed (File/Registry/Kernel)",
    "Security_4660": "Object deleted",

    // === Scheduled Tasks ===
    "Security_4698": "Scheduled task creation recorded",
    "Security_4699": "Scheduled task deletion recorded",
    "Security_4700": "Scheduled task enabled",
    "Security_4701": "Scheduled task disabled",
    "Security_4702": "Scheduled task modification recorded",

    // === System Log ===
    "System_6": "Driver binary module loaded into system",
    "System_104": "System log cleared!",
    "System_1074": "System shutdown or restart initiated",
    "System_1100": "Event log service shutdown completely",
    "System_6005": "Event log service started (System Boot)",
    "System_6006": "Event log service stopped (Clean Shutdown)",
    "System_6008": "Unexpected system shutdown recorded",
    "System_7034": "Service crashed unexpectedly",
    "System_7035": "Service control request sent",
    "System_7036": "Service status changed (Started or Stopped)",
    "System_7040": "Service startup configuration type changed",
    "System_7045": "New system service installation registered",

    // === PowerShell Log ===
    "PowerShell_400": "PowerShell engine lifecycle started",
    "PowerShell_403": "PowerShell engine lifecycle stopped",
    "PowerShell_4103": "PowerShell module execution logging telemetry",
    "PowerShell_4104": "PowerShell script block execution text recorded",

    // === Task Scheduler Log ===
    "Task Scheduler_106": "Scheduled task registered successfully",
    "Task Scheduler_140": "Scheduled task structure updated",
    "Task Scheduler_141": "Scheduled task dropped or deleted",
    "Task Scheduler_200": "Scheduled task process instance started",
    "Task Scheduler_201": "Scheduled task process instance completed",

    // === Windows Defender Log ===
    "Windows Defender_1116": "Defender threat/malware detected on system",
    "Windows Defender_1117": "Defender took programmatic action against threat signature",
    "Windows Defender_1118": "Defender successfully remediated malware threat",
    "Windows Defender_5001": "Real-time protection disabled!",
    "Windows Defender_5007": "Defender engine configuration settings changed",
    "Windows Defender_5010": "Malware protection configuration changed",
    "Windows Defender_5012": "Real-time protection settings changed",

    // === NTFS / Filesystem Log ===
    "NTFS_4": "Storage volume mounted or dismounted",
    "NTFS_98": "NTFS volume metadata changes processed",
    "NTFS_142": "USN journal background activity update",
    "NTFS_501": "USN journal record erased or deleted",

    // === WMI Activity Log ===
    "WMI_5857": "WMI execution provider instance started",
    "WMI_5858": "WMI system activity or query execution processed",
    "WMI_5860": "WMI permanent event consumer framework registration",

    // === Sysmon Log ===
    "Sysmon_1": "Sysmon: Process creation telemetry captured",
    "Sysmon_2": "Sysmon: File creation time changed (Timestomping detected)",
    "Sysmon_3": "Sysmon: Network connection handshake established",
    "Sysmon_5": "Sysmon: Process terminated",
    "Sysmon_6": "Sysmon: Driver loaded",
    "Sysmon_7": "Sysmon: Image binary module loaded (DLL load)",
    "Sysmon_8": "Sysmon: CreateRemoteThread API injection vector detected",
    "Sysmon_10": "Sysmon: High-level process access handle requested",
    "Sysmon_11": "Sysmon: File handle creation timestamped",
    "Sysmon_12": "Sysmon: Registry object created or removed",
    "Sysmon_13": "Sysmon: Registry object value modified",
    "Sysmon_14": "Sysmon: Registry key/value renamed",
    "Sysmon_15": "Sysmon: FileCreateStreamHash (Alternate Data Streams)",
    "Sysmon_17": "Sysmon: Named pipe created",
    "Sysmon_18": "Sysmon: Named pipe connected",
    "Sysmon_22": "Sysmon: Local or WAN DNS query captured",

    // === Firewall Log ===
    "Firewall_1040": "Firewall core rules configuration changed",
    "Firewall_1042": "Firewall isolation rule added or modified"
};

const STRUCTURED_TARGETS = {
    "Security": [
        4616, 4624, 4625, 4627, 4634, 4647, 4648, 4649, 4656, 4660, 4663, 4672, 4673,
        4674, 4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4722, 4723,
        4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4757, 4768, 4769,
        4771, 4776, 4778, 4779, 1102
    ],
    "System": [6, 104, 1074, 1100, 6005, 6006, 6008, 7034, 7035, 7036, 7040, 7045],
    "PowerShell": [400, 403, 4103, 4104],
    "Task Scheduler": [106, 140, 141, 200, 201],
    "Windows Defender": [1116, 1117, 1118, 5001, 5007, 5010, 5012],
    "NTFS": [4, 98, 142, 501],
    "WMI": [5857, 5858, 5860],
    "Sysmon": [1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22],
    "Firewall": [1040, 1042]
};

// ============================================================================
//                          HELPER METHODS
// ============================================================================

function getSystemMachineName() {
    const pcName = process.env.COMPUTERNAME || os.hostname() || "UNKNOWN-PC";
    return pcName.trim().toUpperCase();
}

function getEventLogPhysicalPath(logPath) {
    const sysRoot = process.env.SystemRoot || process.env.WINDIR || "C:\\Windows";
    let convertedFileName = logPath.replace(/\//g, "%4");

    if (logPath.includes("/") && !convertedFileName.includes("%4")) {
        convertedFileName = logPath.replace("/", "%4");
    }

    return `${sysRoot}\\System32\\Winevt\\Logs\\${convertedFileName}.evtx`;
}

function fetchWindowsEvents(channelName, logPath, idList, maxItems = 100) {
    return new Promise((resolve) => {
        const idsString = idList.join(",");
        const pcName = getSystemMachineName();

        const timeoutId = setTimeout(() => {
            console.warn(`[TIMEOUT] Query for ${channelName} took too long and was aborted.`);
            resolve([]);
        }, 3000);

        const rawScript = `
            $ErrorActionPreference = 'Stop';
            try {

                $startTime = (Get-Date).AddMonths(-3);

                $logs = @(Get-WinEvent -FilterHashtable @{
                    LogName="${logPath}";
                    Id=@(${idsString});
                    StartTime=$startTime
                } -MaxEvents ${maxItems} -ErrorAction SilentlyContinue);

                $exactPath = "UNKNOWN";
                try { 
                    $logDetails = Get-WinEvent -ListLog "${logPath}" -ErrorAction SilentlyContinue;
                    if ($logDetails) { $exactPath = $logDetails.LogFilePath }
                } catch {}

                if ($logs.Count -gt 0) {
                    $out = $logs | ForEach-Object {
                        [PSCustomObject]@{
                            Id=$_.Id;
                            TimeCreated=$_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss");
                            LogPath=$exactPath
                        }
                    };
                    return ConvertTo-Json -InputObject $out -Compress;
                }

                return (ConvertTo-Json -InputObject @(@{Empty=$true; LogPath=$exactPath}) -Compress);

            } catch {
                $msg = $_.Exception.Message;
                if ($msg -like "*was not found*" -or $msg -like "*exist*") {
                    return (ConvertTo-Json -InputObject @(@{ChannelMissing=$true}) -Compress);
                }
                return (ConvertTo-Json -InputObject @(@{AccessDenied=$true}) -Compress);
            }
        `;

        const cleanScript = rawScript
            .replace(/\r?\n|\r/g, " ")
            .replace(/\s+/g, " ")
            .trim();

        const base64Script = Buffer.from(cleanScript, "utf16le").toString("base64");

        const windir = process.env.SystemRoot || process.env.WINDIR || "C:\\Windows";
        const isWow64 = process.arch === "ia32" && process.env.PROCESSOR_ARCHITEW6432 !== undefined;
        const psFolder = isWow64 ? `${windir}\\Sysnative` : `${windir}\\System32`;
        const psPath = `${psFolder}\\WindowsPowerShell\\v1.0\\powershell.exe`;

        const psCommand = `"${psPath}" -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${base64Script}`;

        exec(psCommand, { maxBuffer: 1024 * 1024 * 16 }, (error, stdout) => {
            clearTimeout(timeoutId);

            if (error) {
                console.warn(`[EXECUTION WARNING] Running structural fetch failed for ${channelName}.`);
                return resolve([]);
            }

            const cleanStdout = stdout.trim();
            if (!cleanStdout) return resolve([]);

            try {
                let parsedData = JSON.parse(cleanStdout);
                if (!Array.isArray(parsedData)) parsedData = [parsedData];

                const firstNode = parsedData[0];
                if (!firstNode) return resolve([]);

                if (firstNode.ChannelMissing === true || firstNode.ChannelMissing === "True") {
                    return resolve([]);
                }

                if (firstNode.AccessDenied === true || firstNode.AccessDenied === "True") {
                    return resolve([]);
                }

                if (firstNode.Empty === true || firstNode.Empty === "True") {
                    return resolve([]);
                }

                const verifiedLogs = parsedData.map(log => {
                    const eventId = parseInt(log.Id);
                    const validPath = log.LogPath && log.LogPath !== 'UNKNOWN';
                    let discoveredPath = validPath ? log.LogPath : getEventLogPhysicalPath(logPath);

                    if (discoveredPath.includes("%SystemRoot%")) {
                        const actualRoot = process.env.SystemRoot || "C:\\Windows";
                        discoveredPath = discoveredPath.replace("%SystemRoot%", actualRoot);
                    }

                    const lookupKey = `${channelName}_${eventId}`;

                    return {
                        id: eventId,
                        msg: LOG_ID_MESSAGES[lookupKey] || "Event detail logged",
                        pcName: pcName,
                        exactPath: discoveredPath,
                        type: channelName,
                        time: log.TimeCreated || "N/A"
                    };
                });

                return resolve(verifiedLogs);

            } catch (e) {
                return resolve([]);
            }
        });
    });
}

// ============================================================================
//            PROCESSING LIFECYCLE & SCAN PIPELINES
// ============================================================================

async function scanSingleChannel(channelName, maxItems = 100) {
    if (!STRUCTURED_TARGETS[channelName]) return [];

    const internalPath = CHANNEL_LOG_PATHS[channelName];
    const detectedLogs = await fetchWindowsEvents(
        channelName,
        internalPath,
        STRUCTURED_TARGETS[channelName],
        maxItems
    );

    if (typeof window === "undefined" || typeof window.dispatchEvent !== "function") {
        return detectedLogs;
    }

    detectedLogs.forEach(logItem => {
        window.dispatchEvent(new CustomEvent("ui-update", { detail: logItem }));
    });

    return detectedLogs;
}

async function scanAllChannels() {
    const tasks = Object.keys(STRUCTURED_TARGETS).map(channelName =>
        scanSingleChannel(channelName, 100)
    );

    await Promise.all(tasks);
}

// ============================================================================
//                         SCHEMA SYNCHRONIZATION
// ============================================================================

function syncIdInformationCatalog() {
    const descriptiveDatabase = [];

    Object.keys(STRUCTURED_TARGETS).forEach(channelKey => {
        STRUCTURED_TARGETS[channelKey].forEach(id => {
            const lookupKey = `${channelKey}_${id}`;
            if (!LOG_ID_MESSAGES[lookupKey]) return;

            const fullMessage = LOG_ID_MESSAGES[lookupKey];

            const title =
                fullMessage.includes(" (")
                    ? fullMessage.split(" (")[0].trim()
                    : fullMessage.length > 60
                        ? fullMessage.slice(0, 60).trim() + "..."
                        : fullMessage;

            descriptiveDatabase.push({
                id: id,
                type: channelKey,
                title: title,
                desc: fullMessage
            });
        });
    });

    if (typeof window === "undefined" || typeof window.dispatchEvent !== "function") return;

    window.dispatchEvent(
        new CustomEvent("id-info-update", { detail: descriptiveDatabase })
    );
}

// ============================================================================
//                        RUNTIME HOOK INTERFACES
// ============================================================================

if (typeof window !== "undefined") {
    window.api = {
        refreshChannel: async (channelKey) => {
            if (channelKey === "all") {
                await scanAllChannels();
                return;
            }
            if (channelKey === "id-information") return;

            await scanSingleChannel(channelKey, 100);
        }
    };
}

if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
        setTimeout(() => {
            syncIdInformationCatalog();
            scanAllChannels();
        }, 300);
    });
}