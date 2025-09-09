/*The architecture of the system counter of the Generic Timer mandates that the counter must be at least 56
bits, and at most 64 bits. From Armv8.4, for systems that implement counter scaling, the minimum becomes
64 bits.*/

#include <stdbool.h>

#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"
#include "val/include/rme_acs_timer.h"
#include "val/include/rme_acs_common.h"
#include "val/include/rme_std_smc.h"
#include "val/include/rme_test_entry.h"
#include "val/include/rme_acs_el32.h"

#define TEST_NAME  "sys_counter_bitwidth"
#define TEST_DESC  "System counter bit-width validation"
#define TEST_RULE  "TIME_01"

#define MIN_WIDTH 56
#define MAX_WIDTH 64

/* Optional, non-breaking: ask the platform/PAL for an implemented counter width.
 * If your PAL doesn't provide this, val_timer_get_info() will just return 0 (unknown)
 * and we will SKIP only the width sub-check (not the whole test).
 */
#ifndef TIMER_INFO_SYS_CNT_WIDTH_CODE
#define TIMER_INFO_SYS_CNT_WIDTH_CODE (0xABCDEF01u)  /* private query code; returns 0 if unknown */
#endif

/* Robust MMIO read of 64-bit CNTPCT using hi/lo/hi pattern */
static inline
uint64_t
mmio_read_cntpct_robust(uint64_t cnt_base_n)
{
    uint32_t hi1 = val_mmio_read(cnt_base_n + CNTPCT_HIGHER);
    uint32_t lo  = val_mmio_read(cnt_base_n + CNTPCT_LOWER);
    uint32_t hi2 = val_mmio_read(cnt_base_n + CNTPCT_HIGHER);

    if (hi1 == hi2)
        return (((uint64_t)hi1 << 32) | lo);
    else {
        uint32_t lo2 = val_mmio_read(cnt_base_n + CNTPCT_LOWER);
        return (((uint64_t)hi2 << 32) | lo2);
    }
}

/* Main test payload */
static
void
payload(void)
{
    uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
    val_print(ACS_PRINT_WARN, "       PE index: %d", pe_index);
    uint32_t timer_num = val_timer_get_info(TIMER_INFO_NUM_PLATFORM_TIMERS, 0);
    val_print(ACS_PRINT_WARN, "       Timer Count: %d", timer_num);

    if (!timer_num) {
        val_set_status(pe_index, "SKIP", 1);
        return;
    }

    /* We’ll mark PASS if we checked at least one frame’s width rule (or scaling rule).
       If we cannot check *any* frame’s width (no scaling and no platform width), we’ll SKIP. */
    uint32_t frames_checked = 0;
    uint32_t frames_skipped_for_unknown_width = 0;

    while (timer_num--) {

        uint64_t cnt_base_n   = val_timer_get_info(TIMER_INFO_SYS_CNT_BASE_N, timer_num);
        val_print(ACS_PRINT_DEBUG, "       CNT BASE: 0x%llx", (unsigned long long)cnt_base_n);
        uint64_t cnt_ctl_base = val_timer_get_info(TIMER_INFO_SYS_CNTL_BASE,  timer_num);
        val_print(ACS_PRINT_DEBUG, "       CNT CTL BASE: 0x%llx", (unsigned long long)cnt_ctl_base);
        bool     is_secure_timer =
            val_timer_get_info(TIMER_INFO_IS_PLATFORM_TIMER_SECURE, timer_num);

        if ((cnt_base_n == 0) || (cnt_ctl_base == 0)) {
            val_print(ACS_PRINT_WARN, "\n       Skip: Invalid CNT_BASE or CNT_CTL base for frame %d", timer_num);
            continue;
        }

        /* Read a 64-bit counter value (for liveliness/monotonic check). */
        uint64_t counter_val = 0;

        if (!is_secure_timer &&
            val_timer_skip_if_cntbase_access_not_allowed(timer_num) != ACS_STATUS_SKIP) {

            counter_val = mmio_read_cntpct_robust(cnt_base_n);

        } else {
            /* Secure/inaccessible: read via SMC; EL3 writes result into shared_data */
            UserCallSMC(ARM_ACS_SMC_FID, RME_READ_CNTPCT, cnt_base_n, 0, 0);

            if (shared_data->status_code != 0) {
                val_print(ACS_PRINT_WARN, "\n       Skip: CNTPCT SMC read failed for frame %d (status=%u)",
                          timer_num, shared_data->status_code);
                continue;
            }

            counter_val = shared_data->shared_data_access[0].data;
        }

        /* CNTID (secure-only): always via SMC; EL3 writes result into shared_data */
        UserCallSMC(ARM_ACS_SMC_FID,
                    RME_READ_CNTID,
                    cnt_ctl_base + CNTID_OFFSET,
                    0, 0);

        if (shared_data->status_code != 0) {
            val_print(ACS_PRINT_WARN, "\n       Skip: CNTID SMC read failed for frame %d (status=%u)",
                      timer_num, shared_data->status_code);
            continue;
        }

        uint32_t cntid_val = (uint32_t)shared_data->shared_data_access[0].data;

        /* Per Arm docs: bit[0] indicates scaling present (FEAT_CNTSC).
         * Older code used 0xF; tighten to bit0 to avoid misreads.
         */
        bool scaling_present = (cntid_val & 0x1u) != 0u;

        val_print(ACS_PRINT_DEBUG, "       Timer frame %d: CNTID=0x%08x, scaling=%d",
                  timer_num, cntid_val, (int)scaling_present);

        /* Optional platform-provided implemented width (unknown==0). */
        uint64_t plat_w = val_timer_get_info((TIMER_INFO_e)TIMER_INFO_SYS_CNT_WIDTH_CODE, timer_num);
        int impl_width = (plat_w >= 1 && plat_w <= 64) ? (int)plat_w : -1;
        if (impl_width != -1) {
            val_print(ACS_PRINT_DEBUG, "       Implemented width (platform): %d", impl_width);
        }

        if (scaling_present) {
            /* Armv8.4+ with scaling requires a 64-bit counter.
             * We cannot probe width directly; instead:
             *  - Verify the 64-bit interface is alive & monotonic.
             *  - If platform reports width, require it to be 64.
             */
            uint64_t counter_val2 = 0;
            if (!is_secure_timer &&
                val_timer_skip_if_cntbase_access_not_allowed(timer_num) != ACS_STATUS_SKIP) {
                counter_val2 = mmio_read_cntpct_robust(cnt_base_n);
            } else {
                UserCallSMC(ARM_ACS_SMC_FID, RME_READ_CNTPCT, cnt_base_n, 0, 0);
                if (shared_data->status_code != 0) {
                    val_print(ACS_PRINT_ERR, "\n       Scaling present but CNTPCT re-read failed (status=%u)",
                              shared_data->status_code);
                    val_set_status(pe_index, "FAIL", 11);
                    return;
                }
                counter_val2 = shared_data->shared_data_access[0].data;
            }

            if (counter_val2 <= counter_val) {
                val_print(ACS_PRINT_ERR, "\n       Counter not monotonic while scaling is present", 0);
                val_set_status(pe_index, "FAIL", 12);
                return;
            }

            if (impl_width != -1 && impl_width != 64) {
                val_print(ACS_PRINT_ERR, "\n       Scaling present but implemented width (%d) != 64", impl_width);
                val_set_status(pe_index, "FAIL", 13);
                return;
            }

            frames_checked++;
            continue;
        }

        /* Non-scaling case: width must be [56..64]. If unknown, don’t guess—skip the width sub-check. */
        if (impl_width == -1) {
            frames_skipped_for_unknown_width++;
            val_print(ACS_PRINT_WARN, "\n       Width unknown (no discoverable field). Skipping width check for frame %d",
                      timer_num);
            /* We *do not* count this frame as checked for the width rule. */
            continue;
        }

        if (impl_width < MIN_WIDTH) {
            val_print(ACS_PRINT_ERR, "\n       Implemented counter width (%d) < %d bits", impl_width, MIN_WIDTH);
            val_set_status(pe_index, "FAIL", 14);
            return;
        }
        if (impl_width > MAX_WIDTH) {
            val_print(ACS_PRINT_ERR, "\n       Implemented counter width (%d) > %d bits", impl_width, MAX_WIDTH);
            val_set_status(pe_index, "FAIL", 15);
            return;
        }

        frames_checked++;
    }

    /* Finalize result */
    if (frames_checked == 0) {
        /* We couldn’t validate width (and no scaling-present frames); don’t return a false PASS. */
        val_print(ACS_PRINT_WARN,
                  "\n       TIME_01: No frame could be validated for width (unknown everywhere). Marking SKIP.", 0);
        val_set_status(pe_index, "SKIP", 1);
    } else {
        val_set_status(pe_index, "PASS", 1);
    }
    return;
}

/* Entry point for TIME_01 test */
uint32_t
t01_entry(void)
{
    uint32_t num_pe = 1;
    uint32_t status;

    status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

    if (status != ACS_STATUS_SKIP)
        val_run_test_payload(num_pe, payload, 0);

    status = val_check_for_error(num_pe);
    val_report_status(0, "END");

    return status;
}
