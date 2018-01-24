#include <stdlib.h>
#include "npdm.h"
#include "utils.h"
#include "settings.h"
#include "rsa.h"

const char *svc_names[0x80] = {
    "svcUnknown",
    "svcSetHeapSize",
    "svcSetMemoryPermission",
    "svcSetMemoryAttribute",
    "svcMapMemory",
    "svcUnmapMemory",
    "svcQueryMemory",
    "svcExitProcess",
    "svcCreateThread",
    "svcStartThread",
    "svcExitThread",
    "svcSleepThread",
    "svcGetThreadPriority",
    "svcSetThreadPriority",
    "svcGetThreadCoreMask",
    "svcSetThreadCoreMask",
    "svcGetCurrentProcessorNumber",
    "svcSignalEvent",
    "svcClearEvent",
    "svcMapSharedMemory",
    "svcUnmapSharedMemory",
    "svcCreateTransferMemory",
    "svcCloseHandle",
    "svcResetSignal",
    "svcWaitSynchronization",
    "svcCancelSynchronization",
    "svcArbitrateLock",
    "svcArbitrateUnlock",
    "svcWaitProcessWideKeyAtomic",
    "svcSignalProcessWideKey",
    "svcGetSystemTick",
    "svcConnectToNamedPort",
    "svcSendSyncRequestLight",
    "svcSendSyncRequest",
    "svcSendSyncRequestWithUserBuffer",
    "svcSendAsyncRequestWithUserBuffer",
    "svcGetProcessId",
    "svcGetThreadId",
    "svcBreak",
    "svcOutputDebugString",
    "svcReturnFromException",
    "svcGetInfo",
    "svcFlushEntireDataCache",
    "svcFlushDataCache",
    "svcMapPhysicalMemory",
    "svcUnmapPhysicalMemory",
    "svcUnknown",
    "svcGetLastThreadInfo",
    "svcGetResourceLimitLimitValue",
    "svcGetResourceLimitCurrentValue",
    "svcSetThreadActivity",
    "svcGetThreadContext3",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcDumpInfo",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcCreateSession",
    "svcAcceptSession",
    "svcReplyAndReceiveLight",
    "svcReplyAndReceive",
    "svcReplyAndReceiveWithUserBuffer",
    "svcCreateEvent",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcSleepSystem",
    "svcReadWriteRegister",
    "svcSetProcessActivity",
    "svcCreateSharedMemory",
    "svcMapTransferMemory",
    "svcUnmapTransferMemory",
    "svcCreateInterruptEvent",
    "svcQueryPhysicalAddress",
    "svcQueryIoMapping",
    "svcCreateDeviceAddressSpace",
    "svcAttachDeviceAddressSpace",
    "svcDetachDeviceAddressSpace",
    "svcMapDeviceAddressSpaceByForce",
    "svcMapDeviceAddressSpaceAligned",
    "svcMapDeviceAddressSpace",
    "svcUnmapDeviceAddressSpace",
    "svcInvalidateProcessDataCache",
    "svcStoreProcessDataCache",
    "svcFlushProcessDataCache",
    "svcDebugActiveProcess",
    "svcBreakDebugProcess",
    "svcTerminateDebugProcess",
    "svcGetDebugEvent",
    "svcContinueDebugEvent",
    "svcGetProcessList",
    "svcGetThreadList",
    "svcGetDebugThreadContext",
    "svcSetDebugThreadContext",
    "svcQueryDebugProcessMemory",
    "svcReadDebugProcessMemory",
    "svcWriteDebugProcessMemory",
    "svcSetHardwareBreakPoint",
    "svcGetDebugThreadParam",
    "svcUnknown",
    "svcUnknown",
    "svcCreatePort",
    "svcManageNamedPort",
    "svcConnectToPort",
    "svcSetProcessMemoryPermission",
    "svcMapProcessMemory",
    "svcUnmapProcessMemory",
    "svcQueryProcessMemory",
    "svcMapProcessCodeMemory",
    "svcUnmapProcessCodeMemory",
    "svcCreateProcess",
    "svcStartProcess",
    "svcTerminateProcess",
    "svcGetProcessInfo",
    "svcCreateResourceLimit",
    "svcSetResourceLimitLimitValue",
    "svcCallSecureMonitor"
};

#define MAX_FS_PERM_RW 0x27
#define MAX_FS_PERM_int 0x1B
#define FS_PERM_MASK_NODEBUG 0xBFFFFFFFFFFFFFFFULL

const fs_perm_t fs_permissions_rw[MAX_FS_PERM_RW] = {
    {"MountContentType2", 0x8000000000000801},
    {"MountContentType5", 0x8000000000000801},
    {"MountContentType3", 0x8000000000000801},
    {"MountContentType4", 0x8000000000000801},
    {"MountContentType6", 0x8000000000000801},
    {"MountContentType7", 0x8000000000000801},
    {"Unknown (0x6)", 0x8000000000000000},
    {"ContentStorageAccess", 0x8000000000000800},
    {"ImageDirectoryAccess", 0x8000000000001000},
    {"MountBisType28", 0x8000000000000084},
    {"MountBisType29", 0x8000000000000080},
    {"MountBisType30", 0x8000000000008080},
    {"MountBisType31", 0x8000000000008080},
    {"Unknown (0xD)", 0x8000000000000080},
    {"SdCardAccess", 0xC000000000200000},
    {"GameCardUser", 0x8000000000000010},
    {"SaveDataAccess0", 0x8000000000040020},
    {"SystemSaveDataAccess0", 0x8000000000000028},
    {"SaveDataAccess1", 0x8000000000000020},
    {"SystemSaveDataAccess1", 0x8000000000000020},
    {"BisPartition0", 0x8000000000010082},
    {"BisPartition10", 0x8000000000010080},
    {"BisPartition20", 0x8000000000010080},
    {"BisPartition21", 0x8000000000010080},
    {"BisPartition22", 0x8000000000010080},
    {"BisPartition23", 0x8000000000010080},
    {"BisPartition24", 0x8000000000010080},
    {"BisPartition25", 0x8000000000010080},
    {"BisPartition26", 0x8000000000000080},
    {"BisPartition27", 0x8000000000000084},
    {"BisPartition28", 0x8000000000000084},
    {"BisPartition29", 0x8000000000000080},
    {"BisPartition30", 0x8000000000000080},
    {"BisPartition31", 0x8000000000000080},
    {"BisPartition32", 0x8000000000000080},
    {"Unknown (0x23)", 0xC000000000200000},
    {"GameCard_System", 0x8000000000000100},
    {"MountContent_System", 0x8000000000100008},
    {"HostAccess", 0xC000000000400000}
};

const fs_perm_t fs_permissions_int[MAX_FS_PERM_int] = {
    {"BisCache", 0x8000000000000080},
    {"EraseMmc", 0x8000000000000080},
    {"GameCardCertificate", 0x8000000000000010},
    {"GameCardIdSet", 0x8000000000000010},
    {"GameCardDriver", 0x8000000000000200},
    {"GameCardAsic", 0x8000000000000200},
    {"SaveDataCreate", 0x8000000000002020},
    {"SaveDataDelete0", 0x8000000000000060},
    {"SystemSaveDataCreate0", 0x8000000000000028},
    {"SystemSaveDataCreate1", 0x8000000000000020},
    {"SaveDataDelete1", 0x8000000000004028},
    {"SaveDataIterators0", 0x8000000000000060},
    {"SaveDataIterators1", 0x8000000000004020},
    {"SaveThumbnails", 0x8000000000020000},
    {"PosixTime", 0x8000000000000400},
    {"SaveDataExtraData", 0x8000000000004060},
    {"GlobalMode", 0x8000000000080000},
    {"SpeedEmulation", 0x8000000000080000},
    {"(NULL)", 0},
    {"PaddingFiles", 0xC000000000800000},
    {"SaveData_Debug", 0xC000000001000000},
    {"SaveData_SystemManagement", 0xC000000002000000},
    {"Unknown (0x16)", 0x8000000004000000},
    {"Unknown (0x17)", 0x8000000008000000},
    {"Unknown (0x18)", 0x8000000010000000},
    {"Unknown (0x19)", 0x8000000000000800},
    {"Unknown (0x1A)", 0x8000000000004020}
};

char *npdm_get_proc_category(npdm_t *npdm) {
    switch (npdm->process_category) {
        case 0:
            return "Regular Title";
        case 1:
            return "Kernel Built-In";
        default:
            return "Unknown";
    }
}

char *kac_get_app_type(uint32_t app_type) {
    switch (app_type) {
        case 0:
            return "System Module";
        case 1:
            return "Application";
        case 2:
            return "Applet";
        default:
            return "Unknown";
    }
}

void kac_add_mmio(kac_t *kac, kac_mmio_t *mmio) {
    /* Perform an ordered insertion. */
    if (kac->mmio == NULL || mmio->address < kac->mmio->address) {
        mmio->next = kac->mmio;
        kac->mmio = mmio;
    } else {
        kac_mmio_t *ins_mmio = kac->mmio;
        while (ins_mmio != NULL) {
            if (ins_mmio->address < mmio->address) {
                if (ins_mmio->next != NULL) {
                    if (ins_mmio->next->address > mmio->address) {
                        mmio->next = ins_mmio->next;
                        ins_mmio->next = mmio;
                        break;
                    }
                } else {
                    ins_mmio->next = mmio;
                    break;
                }
            }
            if (ins_mmio->next == NULL) {
                ins_mmio->next = mmio;
                break;
            }
            ins_mmio = ins_mmio->next;
        }
    }
}

void kac_print(uint32_t *descriptors, uint32_t num_descriptors) {
    kac_t kac;
    kac_mmio_t *cur_mmio = NULL;
    kac_mmio_t *page_mmio = NULL;
    kac_irq_t *cur_irq = NULL;
    unsigned int syscall_base;
    memset(&kac, 0, sizeof(kac));
    for (uint32_t i = 0; i < num_descriptors; i++) {
        uint32_t desc = descriptors[i];
        if (desc == 0xFFFFFFFF) {
            continue;
        }
        unsigned int low_bits = 0;
        while (desc & 1) {
            desc >>= 1;
            low_bits++;
        }
        desc >>= 1;
        switch (low_bits) {
            case 3: /* Kernel flags. */
                kac.has_kern_flags = 1;
                kac.highest_thread_prio = desc & 0x3F;
                desc >>= 6;
                kac.lowest_thread_prio = desc & 0x3F;
                desc >>= 6;
                kac.lowest_cpu_id = desc & 0xFF;
                desc >>= 8;
                kac.highest_cpu_id = desc & 0xFF;
                break;
            case 4: /* Syscall mask. */
                syscall_base = (desc >> 24) * 0x18;
                for (unsigned int sc = 0; sc < 0x18; sc++) {
                    kac.svcs_allowed[syscall_base+sc] = desc & 1;
                    desc >>= 1;
                }
                break;
            case 6: /* Map IO/Normal. */
                if (cur_mmio == NULL) {
                    cur_mmio = calloc(1, sizeof(kac_mmio_t));
                    if (cur_mmio == NULL) {
                        fprintf(stderr, "Failed to allocate MMIO descriptor!\n");
                        exit(EXIT_FAILURE);
                    }
                    cur_mmio->address = (desc & 0xFFFFFF) << 12;
                    cur_mmio->is_ro = desc >> 24;
                } else {
                    cur_mmio->size = (desc & 0xFFFFFF) << 12;
                    cur_mmio->is_norm = desc >> 24;
                    kac_add_mmio(&kac, cur_mmio);
                    cur_mmio = NULL;
                }
                break;
            case 7: /* Map Normal Page. */
                page_mmio = calloc(1, sizeof(kac_mmio_t));
                if (page_mmio == NULL) {
                    fprintf(stderr, "Failed to allocate MMIO descriptor!\n");
                    exit(EXIT_FAILURE);
                }
                page_mmio->address = desc << 12;
                page_mmio->size = 0x1000;
                page_mmio->is_ro = 0;
                page_mmio->is_norm = 0;
                page_mmio->next = NULL;
                kac_add_mmio(&kac, page_mmio);
                page_mmio = NULL;
                break;
            case 11: /* IRQ Pair. */
                cur_irq = calloc(1, sizeof(kac_irq_t));
                if (cur_irq == NULL) {
                    fprintf(stderr, "Failed to allocate IRQ descriptor!\n");
                    exit(EXIT_FAILURE);
                }
                cur_irq->irq0 = desc & 0x3FF;
                cur_irq->irq1 = (desc >> 10) & 0x3FF;
                if (kac.irqs == NULL) {
                    kac.irqs = cur_irq;
                } else {
                    kac_irq_t *tail_irq = kac.irqs;
                    while (tail_irq->next != NULL) {
                        tail_irq = tail_irq->next;
                    }
                    tail_irq->next = cur_irq;
                }
                cur_irq = NULL;
                break;
            case 13: /* App Type. */
                kac.has_app_type = 1;
                kac.application_type = desc & 7;
                break;
            case 14: /* Kernel Release Version. */
                kac.has_kern_ver = 1;
                kac.kernel_release_version = desc;
                break;
            case 15: /* Handle Table Size. */
                kac.has_handle_table_size = 1;
                kac.handle_table_size = desc;
                break;
            case 16: /* Debug Flags. */
                kac.has_debug_flags = 1;
                kac.allow_debug = desc & 1;
                kac.force_debug = (desc >> 1) & 1;
                break;
        }
    }

    if (kac.has_kern_flags) {
        printf("        Lowest Allowed Priority:    %"PRId8"\n", kac.lowest_thread_prio);
        printf("        Highest Allowed Priority:   %"PRId8"\n", kac.highest_thread_prio);
        printf("        Lowest Allowed CPU ID:      %"PRId8"\n", kac.lowest_cpu_id);
        printf("        Highest Allowed CPU ID:     %"PRId8"\n", kac.highest_cpu_id);

    }

    int first_svc = 1;
    for (unsigned int i = 0; i < 0x80; i++) {
        if (kac.svcs_allowed[i]) {
            printf(first_svc ? "        Allowed SVCs:               %-35s (0x%02"PRIx8")\n" : "                                    %-35s (0x%02"PRIx8")\n", svc_names[i], i);
            first_svc = 0;
        }
    }

    int first_mmio = 1;
    if (kac.mmio != NULL) {
        kac_mmio_t *cur_mmio;
        while (kac.mmio != NULL) {
            cur_mmio = kac.mmio;
            printf(first_mmio ? "        Mapped IO:                  " : "                                    ");
            first_mmio = 0;
            printf("(%09"PRIx64"-%09"PRIx64", %s, %s)\n", cur_mmio->address, cur_mmio->address + cur_mmio->size, cur_mmio->is_ro ? "RO" : "RW", cur_mmio->is_norm ? "Normal" : "IO");
            kac.mmio = kac.mmio->next;
            free(cur_mmio);
        }
    }

    if (kac.irqs != NULL) {
        printf("        Mapped Interrupts:          ");
        int num_irqs = 0;
        while (kac.irqs != NULL) {   
            cur_irq = kac.irqs;
            if (cur_irq->irq0 != 0x3FF) {
                if (num_irqs % 8 == 0) {
                    if (num_irqs) printf("\n                                    ");
                } else {
                    printf(", ");
                }
                printf("0x%03"PRIx32, cur_irq->irq0);
                num_irqs++;
            }
            if (cur_irq->irq1 != 0x3FF) {
                if (num_irqs % 8 == 0) {
                    if (num_irqs) printf("\n                                    ");
                } else {
                    printf(", ");
                }
                printf("0x%03"PRIx32, cur_irq->irq1);
                num_irqs++;
            }
            kac.irqs = kac.irqs->next;
            free(cur_irq);
        }
        printf("\n");
    }

    if (kac.has_app_type) {
        printf("        Application Type:           %s\n", kac_get_app_type(kac.application_type));
    }

    if (kac.has_handle_table_size) {
        printf("        Handle Table Size:          %"PRId32"\n", kac.handle_table_size);
    }

    if (kac.has_debug_flags) {
        printf("        Allow Debug:                %s\n", kac.allow_debug ? "YES" : "NO");
        printf("        Force Debug:                %s\n", kac.force_debug ? "YES" : "NO");
    }
}

/* Modified from https://stackoverflow.com/questions/23457305/compare-strings-with-wildcard */
int match(const char *pattern, const char *candidate, int p, int c) {
    if (pattern[p] == '\0') {
        return candidate[c] == '\0';
    } else if (pattern[p] == '*') {
        for (; candidate[c] != '\0'; c++) {
            if (match(pattern, candidate, p+1, c))
            return 1;
        }
        return match(pattern, candidate, p+1, c);
    } else {
        return match(pattern, candidate, p+1, c+1);
    }
}

int sac_matches(sac_entry_t *lst, char *service) {
    sac_entry_t *cur = lst;
    while (cur != NULL) {
        if (match(cur->service, service, 0, 0)) return 1;
        cur = cur->next;
    }
    return 0;
}

void sac_print(char *acid_sac, uint32_t acid_size, char *aci0_sac, uint32_t aci0_size) {
    /* Parse the ACID sac. */
    sac_entry_t *acid_accesses = NULL;
    sac_entry_t *acid_hosts = NULL;
    sac_entry_t *cur_entry = NULL;
    sac_entry_t *temp = NULL;
    uint32_t ofs = 0;
    uint32_t service_len;
    char ctrl;
    while (ofs < acid_size) {
        ctrl = acid_sac[ofs++];
        service_len = (ctrl & 0xF) + 1;
        cur_entry = calloc(1, sizeof(sac_entry_t));
        cur_entry->valid = 1;
        strncpy(cur_entry->service, &acid_sac[ofs], service_len);
        if (ctrl & 0x80 && acid_hosts == NULL) {
            acid_hosts = cur_entry;
        } else if (!(ctrl & 0x80) && acid_accesses == NULL) {
            acid_accesses = cur_entry;
        } else {
            if (ctrl & 0x80) {
                temp = acid_hosts;
            } else {
                temp = acid_accesses;
            }
            while (temp->next != NULL) {
                temp = temp->next;
            }
            temp->next = cur_entry;
        }
        cur_entry = NULL;
        ofs += service_len;
    }

    /* The ACID sac restricts the ACI0 sac... */
    sac_entry_t *aci0_accesses = NULL;
    sac_entry_t *aci0_hosts = NULL;
    ofs = 0;
    while (ofs < aci0_size) {
        ctrl = aci0_sac[ofs++];
        service_len = (ctrl & 0xF) + 1;
        cur_entry = calloc(1, sizeof(sac_entry_t));
        strncpy(cur_entry->service, &aci0_sac[ofs], service_len);
        if (ctrl & 0x80) {
            cur_entry->valid = sac_matches(acid_hosts, cur_entry->service);
        } else {
            cur_entry->valid = sac_matches(acid_accesses, cur_entry->service);
        }
        if (ctrl & 0x80 && aci0_hosts == NULL) {
            aci0_hosts = cur_entry;
        } else if (!(ctrl & 0x80) && aci0_accesses == NULL) {
            aci0_accesses = cur_entry;
        } else {
            if (ctrl & 0x80) {
                temp = aci0_hosts;
            } else {
                temp = aci0_accesses;
            }
            while (temp->next != NULL) {
                temp = temp->next;
            }
            temp->next = cur_entry;
        }
        cur_entry = NULL;
        ofs += service_len;
    }

    int first = 1;
    while (aci0_hosts != NULL) {
        printf(first ? "        Hosts:                      %-16s%s\n" : "                                    %-16s%s\n", aci0_hosts->service, aci0_hosts->valid ? "" : "(Invalid)");
        temp = aci0_hosts;
        aci0_hosts = aci0_hosts->next;
        free(temp);
        first = 0;
    }

    first = 1;
    while (aci0_accesses != NULL) {
        printf(first ? "        Accesses:                   %-16s%s\n" : "                                    %-16s%s\n", aci0_accesses->service, aci0_accesses->valid ? "" : "(Invalid)");
        temp = aci0_accesses;
        aci0_accesses = aci0_accesses->next;
        free(temp);
        first = 0;
    }

    while (acid_hosts != NULL) {
        temp = acid_hosts;
        acid_hosts = acid_hosts->next;
        free(temp);
    }

    while (acid_accesses != NULL) {
        temp = acid_accesses;
        acid_accesses = acid_accesses->next;
        free(temp);
    }
}



void fac_print(fac_t *fac, fah_t *fah) {
    if (fac->version == fah->version) {
        printf("        Version:                    %"PRId8"\n", fac->version);
    } else {
        printf("        Control Version:            %"PRId8"\n", fac->version);
        printf("        Header Version:             %"PRId8"\n", fah->version);
    }
    uint64_t perms = fac->perms & fah->perms;
    printf("        Raw Permissions:            0x%016"PRIx64"\n", perms);
    printf("        RW Permissions:             ");
    for (unsigned int i = 0; i < MAX_FS_PERM_RW; i++) {
        if (fs_permissions_rw[i].mask & perms) {
            if (fs_permissions_rw[i].mask & (perms & FS_PERM_MASK_NODEBUG)) {
                printf("%s\n                                    ", fs_permissions_rw[i].name);
            } else {
                printf("%-32s [DEBUG ONLY]\n                                    ", fs_permissions_rw[i].name);
            }
        }
    }
    printf("\n");
    printf("        intean Permissions:        ");
    for (unsigned int i = 0; i < MAX_FS_PERM_int; i++) {
        if (fs_permissions_int[i].mask & perms) {
            if (fs_permissions_int[i].mask & (perms & FS_PERM_MASK_NODEBUG)) {
                printf("%s\n                                    ", fs_permissions_int[i].name);
            } else {
                printf("%-32s [DEBUG ONLY]\n                                    ", fs_permissions_int[i].name);
            }        
        }
    }
    printf("\n");
}


void npdm_print(npdm_t *npdm, ncatool_ctx_t *tool_ctx) {
    printf("NPDM:\n");
    print_magic("    Magic:                          ", npdm->magic);
    printf("    MMU Flags:                      %"PRIx8"\n", npdm->mmu_flags);
    printf("    Main Thread Priority:           %"PRId8"\n", npdm->main_thread_prio);
    printf("    Default CPU ID:                 %"PRIx8"\n", npdm->default_cpuid);
    printf("    Process Category:               %s\n", npdm_get_proc_category(npdm));
    printf("    Main Thread Stack Size:         0x%"PRIx32"\n", npdm->main_stack_size);
    printf("    Title Name:                     %s\n", npdm->title_name);
    npdm_acid_t *acid = npdm_get_acid(npdm);
    npdm_aci0_t *aci0 = npdm_get_aci0(npdm);
    printf("    ACID:\n");
    print_magic("        Magic:                      ", acid->magic);
    if (tool_ctx->action & ACTION_VERIFY) {
        if (rsa2048_pss_verify(acid->modulus, acid->size, acid->signature, tool_ctx->settings.keyset.acid_fixed_key_modulus)) {
            memdump(stdout, "        Signature (GOOD):           ", &acid->signature, 0x100);
        } else {
            memdump(stdout, "        Signature (FAIL):           ", &acid->signature, 0x100);
        }
    } else {
        memdump(stdout, "        Signature:                  ", &acid->signature, 0x100);
    }
    memdump(stdout, "        Header Modulus:             ", &acid->modulus, 0x100);
    printf("        Is Retail:                  %"PRId32"\n", acid->is_retail);
    printf("        Title ID Range:             %016"PRIx64"-%016"PRIx64"\n", acid->title_id_range_min, acid->title_id_range_max);
    printf("    ACI0:\n");
    print_magic("        Magic:                      ", aci0->magic);
    printf("        Title ID:                   %016"PRIx64"\n", aci0->title_id);

    /* Kernel access control. */
    uint32_t *acid_kac = (uint32_t *)((char *)acid + acid->kac_offset);
    uint32_t *aci0_kac = (uint32_t *)((char *)aci0 + aci0->kac_offset);
    if (acid->kac_size == aci0->kac_size && memcmp(acid_kac, aci0_kac, acid->kac_size) == 0) {
        /* Shared KAC. */
        printf("    Kernel Access Control:\n");
        kac_print(acid_kac, acid->kac_size/sizeof(uint32_t));
    } else {
        /* Different KAC. */
        printf("    ACID Kernel Access Control:\n");
        kac_print(acid_kac, acid->kac_size/sizeof(uint32_t));
        printf("    ACI0 Kernel Access Control:\n");
        kac_print(aci0_kac, aci0->kac_size/sizeof(uint32_t));
    }

    /* Service access control. */
    char *acid_sac = ((char *)acid + acid->sac_offset);
    char *aci0_sac = ((char *)aci0 + aci0->sac_offset);
    printf("    Service Access Control:\n");
    sac_print(acid_sac, acid->sac_size, aci0_sac, aci0->sac_size);

    /* FS access control. */
    fac_t *fac = (fac_t *)((char *)acid + acid->fac_offset);
    fah_t *fah = (fah_t *)((char *)aci0 + aci0->fah_offset);
    printf("    Filesystem Access Control:\n");
    fac_print(fac, fah);
}
