/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#ifndef SYSCALLS_WIN_MYPLUG_H
#define SYSCALLS_WIN_MYPLUG_H

#include "private.h"
#include "private_2.h"

class win_syscalls_myplug : public syscalls_myplugin_base
{
public:
    GSList* strings_to_free = nullptr;

    std::array<std::array<addr_t, 2>, 2> sst;

    std::unordered_map<vmi_pid_t, std::vector<syscalls_myplug_ns::syscalls_module>> procs;

    addr_t image_path_name;
    std::string win32k_profile;
    bool win32k_initialized;

    std::unique_ptr<libhook::SyscallHook> load_driver_hook;
    std::unique_ptr<libhook::SyscallHook> create_process_hook;
    std::unique_ptr<libhook::SyscallHook> delete_process_hook;
    std::unique_ptr<libhook::ReturnHook> wait_process_creation_hook;

    bool setup_win32k_syscalls(drakvuf_t drakvuf);

    event_response_t load_driver_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t create_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t create_process_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t delete_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    bool trap_syscall_table_entries(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t cr3, bool ntos, addr_t base, std::array<addr_t, 2> _sst, json_object* json);
    virtual char* win_extract_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscalls_myplug_ns::arg_t& arg, addr_t val);

    void print_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int nr, const char* module, const syscalls_myplug_ns::syscall_t* sc, std::vector<uint64_t> args, privilege_mode_t mode, std::optional<std::string> from_dll, std::optional<std::string> from_parent_dll);

    win_syscalls_myplug(drakvuf_t drakvuf, const syscalls_myplugin_config* config, output_format_t output);
    ~win_syscalls_myplug();
};

namespace syscalls_myplug_ns
{

#define NUMBER_SERVICE_TABLES   2
#define NTOS_SERVICE_INDEX      0
#define WIN32K_SERVICE_INDEX    1
#define TABLE_NUMBER_BITS       1
#define TABLE_OFFSET_BITS       12
#define BITS_PER_ENTRY          4
#define SERVICE_TABLE_SHIFT     (12 - BITS_PER_ENTRY)
#define SERVICE_TABLE_MASK      (((1 << TABLE_NUMBER_BITS) - 1) << BITS_PER_ENTRY)
#define SERVICE_TABLE_TEST      (WIN32K_SERVICE_INDEX << BITS_PER_ENTRY)
#define SERVICE_NUMBER_MASK     ((1 << TABLE_OFFSET_BITS) - 1)

#include "private.h"

typedef struct sst_x64
{
    uint64_t ServiceTable;
    uint64_t CounterTable;
    uint64_t ServiceLimit;
    uint64_t ArgumentTable;
} __attribute__((packed)) system_service_table_x64;

typedef struct sst_x86
{
    uint32_t ServiceTable;
    uint32_t CounterTable;
    uint32_t ServiceLimit;
    uint32_t ArgumentTable;
} __attribute__((packed)) system_service_table_x86;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"


SYSCALL(NtOpenFile, NTSTATUS,
    "FileHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "ShareAccess", "", DIR_IN, ULONG,
    "OpenOptions", "", DIR_IN, ULONG,
);

SYSCALL(NtWriteFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Buffer", "bcount(Length)", DIR_IN, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ByteOffset", "opt", DIR_IN, PLARGE_INTEGER,
    "Key", "opt", DIR_IN, PULONG,
);

// WIN32K

SYSCALL(NtBindCompositionSurface, NTSTATUS);

#pragma clang diagnostic pop

static const syscall_t* nt[] =
{
    &NtWriteFile
};
static const syscall_t* win32k[] =
{
    &NtBindCompositionSurface
};


#define NUM_SYSCALLS_NT sizeof(nt)/sizeof(syscall_t*)
#define NUM_SYSCALLS_WIN32K sizeof(win32k)/sizeof(syscall_t*)
}

#endif
