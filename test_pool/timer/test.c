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
#define ARCH_V8_4 0x84

/* Count number of significant bits in a 64-bit value */
static
uint8_t
get_effective_bit_width(uint64_t val)
{
    uint8_t width = 0;
    while (val) {
        width++;
        val >>= 1;
    }
    return width;
}

/* Get architecture version using ID_AA64MMFR2_EL1.TTL field */
static
uint32_t
get_arch_version(void)
{
    uint64_t reg = val_pe_reg_read(ID_AA64MMFR2_EL1);
    uint8_t ttl = (reg >> 48) & 0xF;
    return (ttl != 0) ? ARCH_V8_4 : 0x80;
}

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
    val_print(ACS_PRINT_WARN, "       Timer Index: %d", timer_num);

    if (!timer_num) {
        val_set_status(pe_index, "SKIP", 1);
        return;
    }

    while (timer_num--) {

        uint64_t cnt_base_n   = val_timer_get_info(TIMER_INFO_SYS_CNT_BASE_N, timer_num);
        val_print(ACS_PRINT_WARN, "       CNT BASE: %d", cnt_base_n);
        uint64_t cnt_ctl_base = val_timer_get_info(TIMER_INFO_SYS_CNTL_BASE,  timer_num);
        val_print(ACS_PRINT_WARN, "       CNT CTL BASE: %d", cnt_ctl_base);
        bool     is_secure_timer =
            val_timer_get_info(TIMER_INFO_IS_PLATFORM_TIMER_SECURE, timer_num);

        if ((cnt_base_n == 0) || (cnt_ctl_base == 0)) {
            val_print(ACS_PRINT_WARN, "\n       Timer: Invalid CNT_BASE or CNT_CTL base", 0);
            val_print(ACS_PRINT_WARN, "       Timer index: %d", timer_num);
            continue;
        }

        uint64_t counter_val = 0;

        /* Non-secure & allowed: read via MMIO directly; else use SMC */
        if (!is_secure_timer &&
            val_timer_skip_if_cntbase_access_not_allowed(timer_num) != ACS_STATUS_SKIP) {

            counter_val = mmio_read_cntpct_robust(cnt_base_n);

        } else {
            /* Secure/inaccessible: read via SMC; EL3 writes result into shared_data */
            UserCallSMC(ARM_ACS_SMC_FID, RME_READ_CNTPCT, cnt_base_n, 0, 0);

            if (shared_data->status_code != 0) {
                val_print(ACS_PRINT_WARN, "\n       CNTPCT SMC read failed", 0);
                val_print(ACS_PRINT_WARN, "       Timer index: %d", timer_num);
                continue;
            }

            counter_val = shared_data->shared_data_access[0].data;
        }

        uint8_t  width = get_effective_bit_width(counter_val);
        uint32_t arch_version = get_arch_version();

        /* CNTID (secure-only): always go through SMC; EL3 writes result into shared_data */
        UserCallSMC(ARM_ACS_SMC_FID,
                          RME_READ_CNTID,
                          cnt_ctl_base + CNTID_OFFSET,
                          0, 0);

        if (shared_data->status_code != 0) {
            val_print(ACS_PRINT_WARN, "\n       CNTID SMC read failed", 0);
            val_print(ACS_PRINT_WARN, "       Timer index: %d", timer_num);
            continue;
        }

        uint32_t cntid_val = (uint32_t)shared_data->shared_data_access[0].data;
        bool     scaling_enabled = ((cntid_val & 0xF) != 0);

        val_print(ACS_PRINT_DEBUG, "\n       Timer index: %d", timer_num);
        val_print(ACS_PRINT_DEBUG, "       width (bits): %d", width);
        val_print(ACS_PRINT_DEBUG, "       scaling_enabled: %d", scaling_enabled);

        if (width > MAX_WIDTH) {
            val_print(ACS_PRINT_ERR, "\n       Counter width exceeds 64 bits", 0);
            val_set_status(pe_index, "FAIL", 1);
            return;
        }

        if ((arch_version >= ARCH_V8_4) && scaling_enabled) {
            if (width != 64) {
                val_print(ACS_PRINT_ERR,
                          "\n       Armv8.4+ with scaling: Counter width != 64", 0);
                val_set_status(pe_index, "FAIL", 2);
                return;
            }
        } else {
            if (width < MIN_WIDTH) {
                val_print(ACS_PRINT_ERR,
                          "\n       Counter width less than 56 bits", 0);
                val_set_status(pe_index, "FAIL", 3);
                return;
            }
        }
    }

    val_set_status(pe_index, "PASS", 1);
    return;
}

/* Entry point for B_TIME_04 test */
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
