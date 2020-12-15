/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * System Memory information
 *
 *   Copyright (C) 2000-2002 Alan Cox <alan@redhat.com>
 *   Copyright (C) 2002-2020 Jean Delvare <jdelvare@suse.de>
 *   Copyright (C) 2020 Bastien Nocera <hadess@hadess.net>
 *
 * Unless specified otherwise, all references are aimed at the "System
 * Management BIOS Reference Specification, Version 3.2.0" document,
 * available from http://www.dmtf.org/standards/smbios.
 *
 * Note to contributors:
 * Please reference every value you add or modify, especially if the
 * information does not come from the above mentioned specification.
 *
 * Additional references:
 *  - Intel AP-485 revision 36
 *    "Intel Processor Identification and the CPUID Instruction"
 *    http://www.intel.com/support/processors/sb/cs-009861.htm
 *  - DMTF Common Information Model
 *    CIM Schema version 2.19.1
 *    http://www.dmtf.org/standards/cim/
 *  - IPMI 2.0 revision 1.0
 *    "Intelligent Platform Management Interface Specification"
 *    http://developer.intel.com/design/servers/ipmi/spec.htm
 *  - AMD publication #25481 revision 2.28
 *    "CPUID Specification"
 *    http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/25481.pdf
 *  - BIOS Integrity Services Application Programming Interface version 1.0
 *    http://www.intel.com/design/archives/wfm/downloads/bisspec.htm
 *  - DMTF DSP0239 version 1.1.0
 *    "Management Component Transport Protocol (MCTP) IDs and Codes"
 *    http://www.dmtf.org/standards/pmci
 *  - "TPM Main, Part 2 TPM Structures"
 *    Specification version 1.2, level 2, revision 116
 *    https://trustedcomputinggroup.org/tpm-main-specification/
 *  - "PC Client Platform TPM Profile (PTP) Specification"
 *    Family "2.0", Level 00, Revision 00.43, January 26, 2015
 *    https://trustedcomputinggroup.org/pc-client-platform-tpm-profile-ptp-specification/
 *  - "RedFish Host Interface Specification" (DMTF DSP0270)
 *    https://www.dmtf.org/sites/default/files/DSP0270_1.0.1.pdf
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>
#include <errno.h>

#include "alloc-util.h"
#include "build.h"
#include "fileio.h"
#include "main-func.h"
#include "unaligned.h"
#include "udev-util.h"

#define SUPPORTED_SMBIOS_VER 0x030300

static const char *arg_source_file = NULL;

#define OUT_OF_SPEC_STR "<OUT OF SPEC>"
#define SYS_FIRMWARE_DIR "/sys/firmware/dmi/tables"
#define SYS_ENTRY_FILE SYS_FIRMWARE_DIR "/smbios_entry_point"
#define SYS_TABLE_FILE SYS_FIRMWARE_DIR "/DMI"

/* Use memory alignment workaround or not */
#ifdef __ia64__
#define ALIGNMENT_WORKAROUND
#endif

struct dmi_header {
        uint8_t type;
        uint8_t length;
        uint16_t handle;
        uint8_t *data;
};

/*
 * Per SMBIOS v2.8.0 and later, all structures assume a little-endian
 * ordering convention.
 */
#define WORD(x) (unaligned_read_le16(x))
#define DWORD(x) (unaligned_read_le32(x))
#define QWORD(x) (unaligned_read_le64(x))

static bool verify_checksum(const uint8_t *buf, size_t len) {
        uint8_t sum = 0;
        size_t a;

        for (a = 0; a < len; a++)
                sum += buf[a];
        return sum == 0;
}

/*
 * Type-independant Stuff
 */

static const char *_dmi_string(const struct dmi_header *dm, uint8_t s) {
        const char *bp = (char *)dm->data;

        bp += dm->length;
        while (s > 1 && *bp) {
                bp += strlen(bp);
                bp++;
                s--;
        }

        if (!*bp)
                return NULL;

        return bp;
}

static const char *dmi_string(const struct dmi_header *dm, uint8_t s) {
        const char *bp;

        if (s == 0)
                return "Not Specified";

        bp = _dmi_string(dm, s);
        if (!bp)
                return "<BAD INDEX>";

        return bp;
}

typedef enum {
        MEMORY_SIZE_UNIT_BYTES,
        MEMORY_SIZE_UNIT_KB
} MemorySizeUnit;

/* shift is 0 if the value is in bytes, 1 if it is in kilobytes */
static void dmi_print_memory_size(
                const char *attr_prefix, const char *attr_suffix,
                int slot_num, uint64_t code, MemorySizeUnit unit) {
        if (unit == MEMORY_SIZE_UNIT_KB)
                code = code << 10;

        if (slot_num >= 0)
                printf("%s_%u_%s=%"PRIu64"\n", attr_prefix, slot_num, attr_suffix, code);
        else
                printf("%s_%s=%"PRIu64"\n", attr_prefix, attr_suffix, code);
}

/*
 * 7.17 Physical Memory Array (Type 16)
 */

static const char *dmi_memory_array_location(uint8_t code) {
        /* 7.17.1 */
        static const char *location[] = {
                [0x01] = "Other",
                "Unknown",
                "System Board Or Motherboard",
                "ISA Add-on Card",
                "EISA Add-on Card",
                "PCI Add-on Card",
                "MCA Add-on Card",
                "PCMCIA Add-on Card",
                "Proprietary Add-on Card",
                "NuBus" /* 0x0A */
        };
        static const char *location_0xA0[] = {
                "PC-98/C20 Add-on Card",
                "PC-98/C24 Add-on Card",
                "PC-98/E Add-on Card",
                "PC-98/Local Bus Add-on Card",
                "CXL Flexbus 1.0" /* 0xA4 */
        };

        if (code < ELEMENTSOF(location) && code[location])
                return location[code];
        if (code >= 0xA0 && code < (ELEMENTSOF(location_0xA0) + 0xA0))
                return location_0xA0[code - 0xA0];
        return OUT_OF_SPEC_STR;
}

static const char *dmi_memory_array_ec_type(uint8_t code) {
        /* 7.17.3 */
        static const char *type[] = {
                [0x01] = "Other",
                "Unknown",
                "None",
                "Parity",
                "Single-bit ECC",
                "Multi-bit ECC",
                "CRC" /* 0x07 */
        };

        if (code < ELEMENTSOF(type) && code[type])
                return type[code];
        return OUT_OF_SPEC_STR;
}

/*
 * 7.18 Memory Device (Type 17)
 */

static void dmi_memory_device_width(
                const char *attr_prefix, const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        /*
         * If no memory module is present, width may be 0
         */
        if (code != 0xFFFF && code != 0)
                printf("%s_%u_%s=%u\n", attr_prefix, slot_num, attr_suffix, code);
}

static void dmi_memory_device_size(unsigned slot_num, uint16_t code) {
        if (code == 0) {
                printf("MEMORY_DEVICE_%u_PRESENT=0\n", slot_num);
                return;
        } else if (code == 0xFFFF) {
                return;
        } else {
                uint64_t s = code & 0x7FFF;
                if (!(code & 0x8000))
                        s <<= 10;
                dmi_print_memory_size("MEMORY_DEVICE", "SIZE", slot_num, s, MEMORY_SIZE_UNIT_KB);
        }
}

static void dmi_memory_device_extended_size(unsigned slot_num, uint32_t code) {
        uint64_t capacity;

        capacity = (uint64_t) code * 1024 * 1024;

        printf("MEMORY_DEVICE_%u_SIZE=%"PRIu64"\n", slot_num, capacity);
}

static void dmi_memory_voltage_value(
                const char *attr_prefix, const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        if (code == 0)
                return;
        if (code % 100 != 0)
                printf("%s_%u_%s=%g\n", attr_prefix, slot_num, attr_suffix, (double)code / 1000);
        else
                printf("%s_%u_%s=%.1g\n", attr_prefix, slot_num, attr_suffix, (double)code / 1000);
}

static const char *dmi_memory_device_form_factor(uint8_t code) {
        /* 7.18.1 */
        static const char *form_factor[] = {
                [0x01] = "Other",
                "Unknown",
                "SIMM",
                "SIP",
                "Chip",
                "DIP",
                "ZIP",
                "Proprietary Card",
                "DIMM",
                "TSOP",
                "Row Of Chips",
                "RIMM",
                "SODIMM",
                "SRIMM",
                "FB-DIMM",
                "Die" /* 0x10 */
        };

        if (code < ELEMENTSOF(form_factor) && code[form_factor])
                return form_factor[code];
        return OUT_OF_SPEC_STR;
}

static void dmi_memory_device_set(unsigned slot_num, uint8_t code) {
        if (code == 0xFF)
                printf("MEMORY_DEVICE_%u_SET=%s\n", slot_num, "Unknown");
        else if (code != 0)
                printf("MEMORY_DEVICE_%u_SET=%u\n", slot_num, code);
}

static const char *dmi_memory_device_type(uint8_t code) {
        /* 7.18.2 */
        static const char *type[] = {
                [0x01] = "Other",
                "Unknown",
                "DRAM",
                "EDRAM",
                "VRAM",
                "SRAM",
                "RAM",
                "ROM",
                "Flash",
                "EEPROM",
                "FEPROM",
                "EPROM",
                "CDRAM",
                "3DRAM",
                "SDRAM",
                "SGRAM",
                "RDRAM",
                "DDR",
                "DDR2",
                "DDR2 FB-DIMM",
                "Reserved",
                "Reserved",
                "Reserved",
                "DDR3",
                "FBD2",
                "DDR4",
                "LPDDR",
                "LPDDR2",
                "LPDDR3",
                "LPDDR4",
                "Logical non-volatile device",
                "HBM",
                "HBM2" /* 0x21 */
        };

        if (code < ELEMENTSOF(type) && code[type])
                return type[code];
        return OUT_OF_SPEC_STR;
}

static void dmi_memory_device_type_detail(unsigned slot_num, uint16_t code) {
        /* 7.18.3 */
        static const char *detail[] = {
                [1] = "Other",
                "Unknown",
                "Fast-paged",
                "Static Column",
                "Pseudo-static",
                "RAMBus",
                "Synchronous",
                "CMOS",
                "EDO",
                "Window DRAM",
                "Cache DRAM",
                "Non-Volatile",
                "Registered (Buffered)",
                "Unbuffered (Unregistered)",
                "LRDIMM"  /* 15 */
        };

        if ((code & 0xFFFE) == 0) {
                printf("MEMORY_DEVICE_%u_TYPE_DETAIL=%s\n", slot_num, "None");
        } else {
                size_t i;
                bool first_element = true;

                printf("MEMORY_DEVICE_%u_TYPE_DETAIL=", slot_num);
                for (i = 1; i < ELEMENTSOF(detail); i++)
                        if (code & (1 << i)) {
                                printf("%s%s", first_element ? "" : " ", detail[i]);
                                first_element = false;
                        }
                printf("\n");
        }
}

static void dmi_memory_device_speed(
                const char *attr_prefix, const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        if (code != 0)
                printf("%s_%u_%s=%u\n", attr_prefix, slot_num, attr_suffix, code);
}

static void dmi_memory_technology(unsigned slot_num, uint8_t code) {
        /* 7.18.6 */
        static const char * const technology[] = {
                [0x01] = "Other",
                "Unknown",
                "DRAM",
                "NVDIMM-N",
                "NVDIMM-F",
                "NVDIMM-P",
                "Intel Optane DC persistent memory" /* 0x07 */
        };
        printf("MEMORY_DEVICE_%u_MEMORY_TECHNOLOGY=%s\n", slot_num,
                        code < ELEMENTSOF(technology) && code[technology] ? technology[code] : OUT_OF_SPEC_STR);
}

static void dmi_memory_operating_mode_capability(unsigned slot_num, uint16_t code) {
        /* 7.18.7 */
        static const char * const mode[] = {
                [1] = "Other",
                "Unknown",
                "Volatile memory",
                "Byte-accessible persistent memory",
                "Block-accessible persistent memory" /* 5 */
        };

        if ((code & 0xFFFE) != 0) {
                size_t i;
                bool first_element = true;

                printf("MEMORY_DEVICE_%u_MEMORY_OPERATING_MODE_CAPABILITY=", slot_num);
                for (i = 1; i < ELEMENTSOF(mode); i++)
                        if (code & (1 << i)) {
                                printf("%s%s", first_element ? "" : " ", mode[i]);
                                first_element = false;
                        }
                printf("\n");
        }
}

static void dmi_memory_manufacturer_id(
                const char *attr_prefix, const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        /* 7.18.8 */
        /* 7.18.10 */
        /* LSB is 7-bit Odd Parity number of continuation codes */
        if (code != 0)
                printf("%s_%u_%s=Bank %d, Hex 0x%02X\n", attr_prefix, slot_num, attr_suffix, (code & 0x7F) + 1, code >> 8);
}

static void dmi_memory_product_id(
                const char *attr_prefix, const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        /* 7.18.9 */
        /* 7.18.11 */
        if (code != 0)
                printf("%s_%u_%s=0x%04X\n", attr_prefix, slot_num, attr_suffix, code);
}

static void dmi_memory_size(
                const char *attr_prefix, const char *attr_suffix,
                unsigned slot_num, uint64_t code) {
        /* 7.18.12 */
        /* 7.18.13 */
        if ((code == 0xFFFFFFFFFFFFFFFFLU) ||
            (code == 0x0))
                return;
        dmi_print_memory_size(attr_prefix, attr_suffix, slot_num, code, MEMORY_SIZE_UNIT_BYTES);
}

static void dmi_decode(const struct dmi_header *h) {
        const uint8_t *data = h->data;
        static unsigned next_slot_num = 0;
        unsigned slot_num;

        /*
         * Note: DMI types 37 and 42 are untested
         */
        switch (h->type) {
        case 16: /* 7.17 Physical Memory Array */
                log_debug("Physical Memory Array");
                if (h->length < 0x0F)
                        break;

                if (data[0x05] != 0x03) /* 7.17.2, Use == "System Memory" */
                        break;

                log_debug("Use: System Memory");
                printf("MEMORY_ARRAY_LOCATION=%s\n",
                       dmi_memory_array_location(data[0x04]));
                if (data[0x06] != 0x03) {
                        printf("MEMORY_ARRAY_EC_TYPE=%s\n",
                               dmi_memory_array_ec_type(data[0x06]));
                }
                if (DWORD(data + 0x07) == 0x80000000) {
                        if (h->length >= 0x17)
                                dmi_print_memory_size("MEMORY_ARRAY", "MAX_CAPACITY", -1, QWORD(data + 0x0F), MEMORY_SIZE_UNIT_BYTES);
                } else {
                        uint64_t capacity;

                        capacity = DWORD(data + 0x07);
                        dmi_print_memory_size("MEMORY_ARRAY", "MAX_CAPACITY", -1, capacity, MEMORY_SIZE_UNIT_KB);
                }
                printf("MEMORY_ARRAY_NUM_DEVICES=%u\n", WORD(data + 0x0D));

                break;

        case 17: /* 7.18 Memory Device */
                slot_num = next_slot_num;
                next_slot_num++;

                log_debug("Memory Device");
                if (h->length < 0x15)
                        break;

                dmi_memory_device_width("MEMORY_DEVICE", "TOTAL_WIDTH", slot_num, WORD(data + 0x08));
                dmi_memory_device_width("MEMORY_DEVICE", "DATA_WIDTH", slot_num, WORD(data + 0x0A));
                if (h->length >= 0x20 && WORD(data + 0x0C) == 0x7FFF)
                        dmi_memory_device_extended_size(slot_num, DWORD(data + 0x1C));
                else
                        dmi_memory_device_size(slot_num, WORD(data + 0x0C));
                if (data[0x0E] != 0x02) {
                        printf("MEMORY_DEVICE_%u_FORM_FACTOR=%s\n", slot_num,
                               dmi_memory_device_form_factor(data[0x0E]));
                }
                dmi_memory_device_set(slot_num, data[0x0F]);
                printf("MEMORY_DEVICE_%u_LOCATOR=%s\n", slot_num, dmi_string(h, data[0x10]));
                printf("MEMORY_DEVICE_%u_BANK_LOCATOR=%s\n", slot_num, dmi_string(h, data[0x11]));
                printf("MEMORY_DEVICE_%u_TYPE=%s\n", slot_num, dmi_memory_device_type(data[0x12]));
                dmi_memory_device_type_detail(slot_num, WORD(data + 0x13));
                if (h->length < 0x17)
                        break;

                dmi_memory_device_speed("MEMORY_DEVICE", "SPEED_MTS", slot_num, WORD(data + 0x15));
                if (h->length < 0x1B)
                        break;

                printf("MEMORY_DEVICE_%u_MANUFACTURER=%s\n", slot_num, dmi_string(h, data[0x17]));
                printf("MEMORY_DEVICE_%u_SERIAL_NUMBER=%s\n", slot_num, dmi_string(h, data[0x18]));
                printf("MEMORY_DEVICE_%u_ASSET_TAG=%s\n", slot_num, dmi_string(h, data[0x19]));
                printf("MEMORY_DEVICE_%u_PART_NUMBER=%s\n", slot_num, dmi_string(h, data[0x1A]));
                if (h->length < 0x1C)
                        break;

                if ((data[0x1B] & 0x0F) != 0)
                        printf("MEMORY_DEVICE_%u_RANK=%u\n", slot_num, data[0x1B] & 0x0F);
                if (h->length < 0x22)
                        break;

                dmi_memory_device_speed("MEMORY_DEVICE", "CONFIGURED_SPEED_MTS", slot_num, WORD(data + 0x20));
                if (h->length < 0x28)
                        break;

                dmi_memory_voltage_value("MEMORY_DEVICE", "MINIMUM_VOLTAGE", slot_num, WORD(data + 0x22));
                dmi_memory_voltage_value("MEMORY_DEVICE", "MAXIMUM_VOLTAGE", slot_num, WORD(data + 0x24));
                dmi_memory_voltage_value("MEMORY_DEVICE", "CONFIGURED_VOLTAGE", slot_num, WORD(data + 0x26));
                if (h->length < 0x34)
                        break;

                dmi_memory_technology(slot_num, data[0x28]);
                dmi_memory_operating_mode_capability(slot_num, WORD(data + 0x29));
                printf("MEMORY_DEVICE_%u_FIRMWARE_VERSION=%s\n", slot_num, dmi_string(h, data[0x2B]));
                dmi_memory_manufacturer_id("MEMORY_DEVICE", "MODULE_MANUFACTURER_ID", slot_num, WORD(data + 0x2C));
                dmi_memory_product_id("MEMORY_DEVICE", "MODULE_PRODUCT_ID", slot_num, WORD(data + 0x2E));
                dmi_memory_manufacturer_id("MEMORY_DEVICE", "MEMORY_SUBSYSTEM_CONTROLLER_MANUFACTURER_ID",
                                           slot_num, WORD(data + 0x30));
                dmi_memory_product_id("MEMORY_DEVICE", "MEMORY_SUBSYSTEM_CONTROLLER_PRODUCT_ID",
                                      slot_num, WORD(data + 0x32));
                if (h->length < 0x3C)
                        break;

                dmi_memory_size("MEMORY_DEVICE", "NON_VOLATILE_SIZE", slot_num, QWORD(data + 0x34));
                if (h->length < 0x44)
                        break;

                dmi_memory_size("MEMORY_DEVICE", "VOLATILE_SIZE", slot_num, QWORD(data + 0x3C));
                if (h->length < 0x4C)
                        break;

                dmi_memory_size("MEMORY_DEVICE", "CACHE_SIZE", slot_num, QWORD(data + 0x44));
                if (h->length < 0x54)
                        break;

                dmi_memory_size("MEMORY_DEVICE", "LOGICAL_SIZE", slot_num, QWORD(data + 0x4C));

                break;
        }
}

static void dmi_table_decode(uint8_t *buf, uint32_t len, uint16_t num, bool stop_at_eot) {
        uint8_t *data;
        int i = 0;

        data = buf;
        /* 4 is the length of an SMBIOS structure header */
        while ((i < num || !num) && data + 4 <= buf + len) {
                uint8_t *next;
                bool display;
                struct dmi_header h = (struct dmi_header) {
                        .type = data[0],
                        .length = data[1],
                        .handle = WORD(data + 2),
                        .data = data
                };

                display = (!(h.type == 126 || h.type == 127));

                /*
                 * If a short entry is found (less than 4 bytes), not only it
                 * is invalid, but we cannot reliably locate the next entry.
                 * Better stop at this point, and let the user know his/her
                 * table is broken.
                 */
                if (h.length < 4)
                        break;
                i++;

                /* In quiet mode, stop decoding at end of table marker */
                if (h.type == 127)
                        break;

                /* Look for the next handle */
                next = data + h.length;
                while ((size_t)(next - buf + 1) < len && (next[0] != 0 || next[1] != 0))
                        next++;
                next += 2;

                /* Make sure the whole structure fits in the table */
                if ((size_t)(next - buf) > len) {
                        data = next;
                        break;
                }

                if (display)
                        dmi_decode(&h);

                data = next;

                /* SMBIOS v3 requires stopping at this marker */
                if (h.type == 127 && stop_at_eot)
                        break;
        }
}

static void dmi_table(int64_t base, uint32_t len, uint16_t num, const char *devmem,
                bool stop_at_eot, bool no_file_offset) {
        _cleanup_free_ uint8_t *buf = NULL;
        size_t size;
        int r;

        /*
         * When reading from sysfs or from a dump file, the file may be
         * shorter than announced. For SMBIOS v3 this is expcted, as we
         * only know the maximum table size, not the actual table size.
         * For older implementations (and for SMBIOS v3 too), this
         * would be the result of the kernel truncating the table on
         * parse error.
         */
        r = read_full_file_full(AT_FDCWD, devmem,
                        no_file_offset ? 0 : base, len,
                        0, NULL, (char **) &buf, &size);
        if (r < 0) {
                log_error_errno(r, "Failed to read table, sorry: %m");
                return;
        }

        len = size;
        dmi_table_decode(buf, len, num, stop_at_eot);
}

/* Same thing for SMBIOS3 entry points */
static int smbios3_decode(uint8_t *buf, const char *devmem, bool no_file_offset) {
        uint64_t offset;

        /* Don't let checksum run beyond the buffer */
        if (buf[0x06] > 0x20) {
                log_error("Entry point length too large (%u bytes, expected %u).",
                          (unsigned)buf[0x06], 0x18U);
                return 0;
        }

        if (!verify_checksum(buf, buf[0x06]))
                return 0;

        offset = QWORD(buf + 0x10);
        if (!no_file_offset && (offset >> 32) != 0 && sizeof(int64_t) < 8) {
                log_error("64-bit addresses not supported, sorry.");
                return 0;
        }

        dmi_table(offset, DWORD(buf + 0x0C), 0, devmem, true, no_file_offset);

        return 1;
}

static int smbios_decode(uint8_t *buf, const char *devmem, bool no_file_offset) {
        /* Don't let checksum run beyond the buffer */
        if (buf[0x05] > 0x20) {
                log_error("Entry point length too large (%u bytes, expected %u).",
                          (unsigned)buf[0x05], 0x1FU);
                return 0;
        }

        if (!verify_checksum(buf, buf[0x05])
            || memcmp(buf + 0x10, "_DMI_", 5) != 0
            || !verify_checksum(buf + 0x10, 0x0F))
                return 0;

        dmi_table(DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C),
                  devmem, false, no_file_offset);

        return 1;
}

static int legacy_decode(uint8_t *buf, const char *devmem, bool no_file_offset) {
        if (!verify_checksum(buf, 0x0F))
                return 0;

        dmi_table(DWORD(buf + 0x08), WORD(buf + 0x06), WORD(buf + 0x0C),
                  devmem, false, no_file_offset);

        return 1;
}

static int parse_argv(int argc, char * const *argv) {
        static const struct option options[] = {
                { "help", no_argument, NULL, 'h' },
                { "from-dump", required_argument, NULL, 'F' },
                { "version", no_argument, NULL, 'V' },
                {}
        };

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "F:hV", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'F':
                        arg_source_file = optarg;
                        break;
                case 'h':
                        printf("Usage: %s [options]\n"
                               " -F,--from-dump FILE   read DMI information from a binary file\n"
                               " -h,--help             print this help text\n\n",
                               program_invocation_short_name);
                        return 0;
                case 'V':
                        printf("%s\n", GIT_VERSION);
                        return 0;
                case '?':
                        return -EINVAL;
                }
        }

        return 0;
}

static int run(int argc, char* const* argv) {
        int r = 0;
        int found = 0;
        size_t size;
        _cleanup_free_ uint8_t *buf = NULL;
        bool no_file_offset = false;

        log_set_target(LOG_TARGET_AUTO);
        udev_parse_config();
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r < 0)
                return r;

        /* Read from dump if so instructed */
        r = read_full_file_full(AT_FDCWD,
                                arg_source_file ?: SYS_ENTRY_FILE,
                                0, 0x20, 0, NULL, (char **) &buf, &size);
        if (r < 0) {
                return log_full_errno(!arg_source_file && r == -ENOENT ? LOG_DEBUG : LOG_ERR,
                                      r, "Reading \"%s\" failed: %m",
                                      arg_source_file ?: SYS_ENTRY_FILE);
        }
        if (!arg_source_file) {
                arg_source_file = SYS_TABLE_FILE;
                no_file_offset = true;
        }

        if (size >= 24 && memcmp(buf, "_SM3_", 5) == 0) {
                if (smbios3_decode(buf, arg_source_file, no_file_offset))
                        found++;
        } else if (size >= 31 && memcmp(buf, "_SM_", 4) == 0) {
                if (smbios_decode(buf, arg_source_file, no_file_offset))
                        found++;
        } else if (size >= 15 && memcmp(buf, "_DMI_", 5) == 0) {
                if (legacy_decode(buf, arg_source_file, no_file_offset))
                        found++;
        }

        if (!found)
                r = EXIT_FAILURE;

        return r;
}

DEFINE_MAIN_FUNCTION(run);
