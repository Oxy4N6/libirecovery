/*
 * irecovery.c
 * iBoot/iBSS communication interface for iOS devices
 *
 * Copyright (c) 2012-2013 Martin Szulecki <m.szulecki@libimobiledevice.org>
 * Copyright (c) 2010-2011 Chronic-Dev Team
 * Copyright (c) 2010-2011 Joshua Hill
 * Copyright (c) 2008-2011 Nicolas Haunold
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */


/*

Modified 07/24/2024

Project changes related to the transition to Unicode support include several key aspects related to text processing and interaction with the operating system:

1. **Transition to the use of wide characters and functions to handle them:**
   
   The code update has transitioned from using standard data types and functions designed to handle narrow characters to their Unicode support-oriented counterparts. In particular, the `char` data type, traditionally used for storing characters, was replaced by the `wchar_t` data type, which is designed to work with wide characters that support UTF-16 encoding. This transition allowed text containing characters from different world languages to be processed and displayed correctly.
   
   Also, standard functions such as `printf`, `strtok` and `fopen`, which use narrow characters, were replaced by their wide-character counterparts: `wprintf`, `wcstok`, `_wfopen`. These changes provided Unicode support and the ability to work with text data in different languages, which is especially important for applications intended for use in an international environment.

2. **Realization of a custom version of the getopt function for Unicode support:**
   
   The `getopt` function provided by the standard C library is limited in its handling of command line arguments represented in narrow character (`char`) format. This creates problems for applications that must support Unicode, especially on systems where the locale may include non-Latin characters.
   
   To solve this problem, a proprietary version of the `getopt` function called `wgetopt` has been developed. This function accepts command line arguments in the wide character format (`wchar_t`), which allows it to correctly handle Unicode-encoded parameters. The `wgetopt` implementation is critical to ensure that the software works properly in environments where many different languages and encodings are used.

3. **Use of conversion functions between wchar_t and char:**
   
   Interacting with libraries and functions that still accept strings in the narrow character format (`char`) required the implementation of mechanisms to convert data between the different formats. For this purpose, the functions `wcstombs`, which performs conversion from the `wchar_t` format to `char`, and `mbstowcs`, which performs the reverse conversion, were used. These functions preserve Unicode support while ensuring compatibility with libraries that do not support wide characters. In this way, it has been possible to maintain data integrity when transferring data between different components of the system.

4. **Error handling and message output:**
   
   During error processing and debugging information output, an important attention was paid to correct displaying of messages containing Unicode characters. For this purpose, the `wprintf` and `fwprintf` functions were used, which are capable of correctly outputting wide characters to the console. This ensures that all messages, regardless of language, will be displayed correctly and completely, which is especially important when diagnosing problems and monitoring program operation.

5. **File handling:**
   
   In the `buffer_read_from_filename` function, which is responsible for reading data from files, the `_wfopen` method was used. This method allows opening files with names containing Unicode characters, which is critical to ensure compatibility with files created in different language locales. Thus, it was made possible to work with files whose names may contain characters from any Unicode-supported languages, which greatly expands the program's capabilities in a multilingual environment.

*/

#pragma warning(disable : 4996)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wchar.h>
#include "libirecovery.h"
#include "getopt.h"

#define SLEEP_MS(ms) Sleep(ms)
#define FORMAT_LLD L"%lld"

#define HISTORY_FILE_PATH L".irecovery"
#define DEBUG_LOG(...) if(verbose_mode) fprintf(stderr, __VA_ARGS__)

typedef enum {
    RESET_DEVICE,
    LAUNCH_SHELL,
    SEND_CMD,
    SEND_DATA_FILE,
    EXEC_EXPLOIT,
    EXEC_SCRIPT,
    DISPLAY_MODE,
    PRINT_SHELL_HEADER,
    REBOOT_NORMAL_MODE
} ActionType;

static unsigned int terminate = 0;
static unsigned int verbose_mode = 0;

static const wchar_t* mode_to_string(int mode);
static int parse_options(int argc, wchar_t* const argv[], const wchar_t* optstring);
static void load_file_to_buffer(const wchar_t* filename, char** buffer, uint64_t* length);
static void execute_command(irecv_client_t client, wchar_t* command);
static void start_shell(irecv_client_t client);
static void convert_hex_to_str(wchar_t* str, int buflen, const unsigned char* buf);
static int convert_str_to_hex(int buflen, unsigned char* buf, const wchar_t* str);
static int handle_received_event(irecv_client_t client, const irecv_event_t* event);
static int handle_pre_command_event(irecv_client_t client, const irecv_event_t* event);
static int handle_post_command_event(irecv_client_t client, const irecv_event_t* event);
static int handle_progress_event(irecv_client_t client, const irecv_event_t* event);
static void display_progress(double progress);
static void show_help_menu();

/* Function to show help menu in the shell */
static void show_help_menu() {
    wprintf(L"Commands:\n");
    wprintf(L"  /upload FILE\t\tsend FILE to device\n");
    wprintf(L"  /limera1n [FILE]\trun limera1n exploit and send optional payload from FILE\n");
    wprintf(L"  /deviceinfo\t\tprint device information (ECID, IMEI, etc.)\n");
    wprintf(L"  /help\t\t\tshow this help\n");
    wprintf(L"  /exit\t\t\texit interactive shell\n");
}

uint32_t crc32(uint8_t* data, uint32_t len) {
    uint32_t crc = 0xFFFFFFFF;

    for (uint32_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        for (uint32_t j = 0; j < 8; j++) {
            uint32_t b = (byte ^ crc) & 1;
            crc >>= 1;
            if (b) {
                crc = crc ^ 0xEDB88320;
            }
            byte >>= 1;
        }
    }

    return ~crc;
}

/* Converts mode integers to readable strings */
static const wchar_t* mode_to_string(int mode) {
    switch (mode) {
    case IRECV_K_RECOVERY_MODE_1:
    case IRECV_K_RECOVERY_MODE_2:
    case IRECV_K_RECOVERY_MODE_3:
    case IRECV_K_RECOVERY_MODE_4:
        return L"Recovery";
    case IRECV_K_DFU_MODE:
        return L"DFU";
    case IRECV_K_WTF_MODE:
        return L"WTF";
    default:
        return L"Unknown";
    }
}

/* Handles the parsing of command-line options */
static int parse_options(int argc, wchar_t* const argv[], const wchar_t* optstring) {
    static int current_index = 1;
    static int current_option = 0;
    static wchar_t* next_char = NULL;
    wchar_t* option_char = NULL;

    if (current_index >= argc || argv[current_index][0] != L'-' || argv[current_index][1] == L'\0') {
        return -1;
    }

    if (argv[current_index][1] == L'-' && argv[current_index][2] == L'\0') {
        current_index++;
        return -1;
    }

    if (next_char == NULL || *next_char == L'\0') {
        next_char = &argv[current_index][1];
    }

    current_option = *next_char++;
    option_char = wcschr(optstring, current_option);

    if (option_char == NULL) {
        wprintf(L"Unknown option: -%c\n", current_option);
        return L'?';
    }

    if (option_char[1] == L':') {
        if (*next_char != L'\0') {
            optarg = next_char;
        }
        else if (current_index + 1 < argc) {
            current_index++;
            optarg = argv[current_index];
        }
        else {
            wprintf(L"Option -%c requires an argument\n", current_option);
            return L'?';
        }
        next_char = NULL;
    }

    current_index++;
    return current_option;
}

/* Loads a file into a buffer */
static void load_file_to_buffer(const wchar_t* filename, char** buffer, uint64_t* length) {
    FILE* file;
    uint64_t file_size;

    *length = 0;

    file = _wfopen(filename, L"rb");
    if (!file) {
        return;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    if (file_size == 0) {
        fclose(file);
        return;
    }

    *buffer = (char*)malloc(sizeof(char) * (file_size + 1));
    fread(*buffer, sizeof(char), file_size, file);
    fclose(file);

    *length = file_size;
}

/* Executes the appropriate command based on user input */
static void execute_command(irecv_client_t client, wchar_t* command) {
    wchar_t* action = wcstok(command, L" ", NULL);

    if (!wcscmp(action, L"/exit")) {
        terminate = 1;
    }
    else if (!wcscmp(action, L"/help")) {
        show_help_menu();
    }
    else if (!wcscmp(action, L"/upload")) {
        wchar_t* filename = wcstok(NULL, L" ", NULL);
        DEBUG_LOG(L"Uploading file %ls\n", filename);
        if (filename != NULL) {
            char* filename_utf8 = NULL;
            size_t filename_size = wcstombs(NULL, filename, 0) + 1;
            filename_utf8 = (char*)malloc(filename_size);
            wcstombs(filename_utf8, filename, filename_size);
            irecv_send_file(client, filename_utf8, 0);
            free(filename_utf8);
        }
    }
    else if (!wcscmp(action, L"/deviceinfo")) {
        int ret, mode;
        unsigned int cpid, bdid;
        unsigned long long ecid;
        char srnm[12], imei[15];

        ret = irecv_get_cpid(client, &cpid);
        if (ret == IRECV_E_SUCCESS) {
            wprintf(L"CPID: %d\n", cpid);
        }

        ret = irecv_get_bdid(client, &bdid);
        if (ret == IRECV_E_SUCCESS) {
            wprintf(L"BDID: %d\n", bdid);
        }

        ret = irecv_get_ecid(client, &ecid);
        if (ret == IRECV_E_SUCCESS) {
            wprintf(L"ECID: " FORMAT_LLD L"\n", ecid);
        }

        ret = irecv_get_srnm(client, srnm);
        if (ret == IRECV_E_SUCCESS) {
            wprintf(L"SRNM: %S\n", srnm);
        }

        ret = irecv_get_imei(client, imei);
        if (ret == IRECV_E_SUCCESS) {
            wprintf(L"IMEI: %S\n", imei);
        }

        ret = irecv_get_mode(client, &mode);
        if (ret == IRECV_E_SUCCESS) {
            wprintf(L"MODE: %s\n", mode_to_string(mode));
        }

    }
    else if (!wcscmp(action, L"/limera1n")) {
        wchar_t* filename = wcstok(NULL, L" ", NULL);
        DEBUG_LOG(L"Sending limera1n payload %ls\n", filename);
        if (filename != NULL) {
            char* filename_utf8 = NULL;
            size_t filename_size = wcstombs(NULL, filename, 0) + 1;
            filename_utf8 = (char*)malloc(filename_size);
            wcstombs(filename_utf8, filename, filename_size);
            irecv_send_file(client, filename_utf8, 0);
            free(filename_utf8);
        }
        irecv_trigger_limera1n_exploit(client);
    }
    else if (!wcscmp(action, L"/execute")) {
        wchar_t* filename = wcstok(NULL, L" ", NULL);
        DEBUG_LOG(L"Executing script %ls\n", filename);
        if (filename != NULL) {
            char* buffer = NULL;
            uint64_t buffer_length = 0;
            load_file_to_buffer(filename, &buffer, &buffer_length);
            if (buffer) {
                buffer[buffer_length] = '\0';
                irecv_execute_script(client, buffer);
                free(buffer);
            }
            else {
                wprintf(L"Could not read file '%ls'\n", filename);
            }
        }
    }

    free(action);
}

/* Initializes and runs the interactive shell */
static void start_shell(irecv_client_t client) {
    setbuf(stdout, NULL);

    irecv_error_t error = 0;
    while (!terminate) {
        error = irecv_receive(client);
        if (error != IRECV_E_SUCCESS) {
            DEBUG_LOG("%s\n", irecv_strerror(error));
            break;
        }

        wprintf(L"> ");
        wchar_t cmd[256] = { 0 };
        fgetws(cmd, 256, stdin);

        if (cmd && *cmd) {
            char* cmd_utf8 = NULL;
            size_t cmd_size = wcstombs(NULL, cmd, 0) + 1;
            cmd_utf8 = (char*)malloc(cmd_size);
            wcstombs(cmd_utf8, cmd, cmd_size);
            error = irecv_send_command(client, cmd_utf8);
            free(cmd_utf8);

            if (error != IRECV_E_SUCCESS) {
                terminate = 1;
            }
        }
    }
}

/* Converts hexadecimal buffer to string representation */
static void convert_hex_to_str(wchar_t* str, int buflen, const unsigned char* buf) {
    static const wchar_t h2a[] = L"0123456789abcdef";
    for (; buflen > 0; --buflen) {
        unsigned char byte = *buf++;
        *str++ = h2a[byte >> 4];
        *str++ = h2a[byte & 0xF];
    }
    *str = L'\0';
}

/* Converts string to hexadecimal buffer */
static int convert_str_to_hex(int buflen, unsigned char* buf, const wchar_t* str) {
    unsigned char* ptr = buf;
    int seq = -1;
    while (buflen > 0) {
        int nibble = *str++;
        if (nibble >= L'0' && nibble <= L'9') {
            nibble -= L'0';
        }
        else {
            nibble |= 0x20;
            if (nibble < L'a' || nibble > L'f') {
                break;
            }
            nibble -= L'a' - 10;
        }
        if (seq >= 0) {
            *buf++ = (seq << 4) | nibble;
            buflen--;
            seq = -1;
        }
        else {
            seq = nibble;
        }
    }
    return buf - ptr;
}

/* Callback function for handling received events */
static int handle_received_event(irecv_client_t client, const irecv_event_t* event) {
    if (event->type == IRECV_RECEIVED) {
        int i = 0;
        int size = event->size;
        const char* data = event->data;
        for (i = 0; i < size; i++) {
            putchar(data[i]);
        }
    }

    return 0;
}

/* Callback function for handling pre-command events */
static int handle_pre_command_event(irecv_client_t client, const irecv_event_t* event) {
    if (event->type == IRECV_PRECOMMAND) {
        if (event->data[0] == '/') {
            wchar_t wdata[256];
            mbstowcs(wdata, event->data, event->size);
            execute_command(client, wdata);
            return -1;
        }
    }

    return 0;
}

/* Callback function for handling post-command events */
static int handle_post_command_event(irecv_client_t client, const irecv_event_t* event) {
    char* value = NULL;
    char* action = NULL;
    char* command = NULL;
    char* argument = NULL;
    irecv_error_t error = IRECV_E_SUCCESS;

    if (event->type == IRECV_POSTCOMMAND) {
        command = strdup(event->data);
        action = strtok(command, " ");
        if (!strcmp(action, "getenv")) {
            argument = strtok(NULL, " ");
            error = irecv_getenv(client, argument, &value);
            if (error != IRECV_E_SUCCESS) {
                DEBUG_LOG("%s\n", irecv_strerror(error));
                free(command);
                return error;
            }
            wprintf(L"%S\n", value);
            free(value);
        }

        if (!strcmp(action, "reboot")) {
            terminate = 1;
        }
    }

    if (command)
        free(command);

    return 0;
}

/* Callback function for handling progress events */
static int handle_progress_event(irecv_client_t client, const irecv_event_t* event) {
    if (event->type == IRECV_PROGRESS) {
        display_progress(event->progress);
    }

    return 0;
}

/* Displays progress as a progress bar */
static void display_progress(double progress) {
    int i = 0;

    if (progress < 0) {
        return;
    }

    if (progress > 100) {
        progress = 100;
    }

    wprintf(L"\r[");

    for (i = 0; i < 50; i++) {
        if (i < progress / 2) {
            wprintf(L"=");
        }
        else {
            wprintf(L" ");
        }
    }

    wprintf(L"] %3.1f%%", progress);

    fflush(stdout);

    if (progress == 100) {
        wprintf(L"\n");
    }
}

/* Prints the usage information for the command-line interface */
static void display_usage(int argc, wchar_t** argv) {
    wchar_t* name = NULL;
    name = wcsrchr(argv[0], L'/');
    wprintf(L"Usage: %s [OPTIONS]\n", (name ? name + 1 : argv[0]));
    wprintf(L"Interact with an iOS device in DFU or recovery mode.\n\n");
    wprintf(L"options:\n");
    wprintf(L"  -i ECID\tconnect to specific device by its hexadecimal ECID\n");
    wprintf(L"  -c CMD\trun CMD on device\n");
    wprintf(L"  -m\t\tprint current device mode\n");
    wprintf(L"  -w\t\tprint shell welcome header\n");
    wprintf(L"  -f FILE\tsend file to device\n");
    wprintf(L"  -k FILE\tsend limera1n usb exploit payload from FILE\n");
    wprintf(L"  -r\t\treset client\n");
    wprintf(L"  -n\t\treboot device into normal mode (exit recovery loop)\n");
    wprintf(L"  -e FILE\texecutes recovery script from FILE\n");
    wprintf(L"  -s\t\tstart an interactive shell\n");
    wprintf(L"  -v\t\tenable verbose output, repeat for higher verbosity\n");
    wprintf(L"  -h\t\tprints this usage information\n");
    wprintf(L"\n");
}

/* Main function to handle command-line input and execute corresponding actions */
int irecovery_main(int argc, wchar_t* argv[]) {
    int i = 0;
    int opt = 0;
    int selected_action = 0;
    unsigned long long ecid = 0;
    int mode = -1;
    wchar_t* argument = NULL;
    irecv_error_t error = 0;

    char* buffer = NULL;
    uint64_t buffer_length = 0;

    if (argc == 1) {
        display_usage(argc, argv);
        return 0;
    }

    while ((opt = parse_options(argc, argv, L"i:vhrsomwnc:f:e:k::")) > 0) {
        switch (opt) {
        case 'i':
            if (optarg) {
                wchar_t* tail = NULL;
                ecid = wcstoull(optarg, &tail, 16);
                if (tail && (tail[0] != L'\0')) {
                    ecid = 0;
                }
                if (ecid == 0) {
                    fwprintf(stderr, L"ERROR: Could not parse ECID from argument '%ls'\n", optarg);
                    return -1;
                }
            }
            break;

        case 'v':
            verbose_mode += 1;
            break;

        case 'h':
            display_usage(argc, argv);
            return 0;

        case 'm':
            selected_action = DISPLAY_MODE;
            break;

        case 'w':
            selected_action = PRINT_SHELL_HEADER;
            break;

        case 'n':
            selected_action = REBOOT_NORMAL_MODE;
            break;

        case 'r':
            selected_action = RESET_DEVICE;
            break;

        case 's':
            selected_action = LAUNCH_SHELL;
            break;

        case 'f':
            selected_action = SEND_DATA_FILE;
            argument = optarg;
            break;

        case 'c':
            selected_action = SEND_CMD;
            argument = optarg;
            break;

        case 'k':
            selected_action = EXEC_EXPLOIT;
            argument = optarg;
            break;

        case 'e':
            selected_action = EXEC_SCRIPT;
            argument = optarg;
            break;

        default:
            fwprintf(stderr, L"Unknown argument\n");
            return -1;
        }
    }

    if (verbose_mode)
        irecv_set_debug_level(verbose_mode);

    irecv_init();
    irecv_client_t client = NULL;
    for (i = 0; i <= 5; i++) {
        DEBUG_LOG(L"Attempting to connect... \n");

        if (irecv_open_with_ecid(&client, ecid) != IRECV_E_SUCCESS)
            SLEEP_MS(1000);
        else
            break;

        if (i == 5) {
            return -1;
        }
    }

    irecv_device_t device = NULL;
    irecv_devices_get_device_by_client(client, &device);
    if (device)
        DEBUG_LOG(L"Connected to %S, model %S, cpid 0x%04x, bdid 0x%02x\n", device->product_type, device->hardware_model, device->chip_id, device->board_id);

    switch (selected_action) {
    case RESET_DEVICE:
        irecv_reset(client);
        break;

    case SEND_DATA_FILE:
        irecv_event_subscribe(client, IRECV_PROGRESS, &handle_progress_event, NULL);
        error = irecv_send_file(client, argument, 1);
        DEBUG_LOG("%s\n", irecv_strerror(error));
        break;

    case SEND_CMD:
        wprintf(L"SEND_CMD\n");
        char* argument_utf8;
        size_t argument_size = wcstombs(NULL, argument, 0) + 1;
        argument_utf8 = (char*)malloc(argument_size);
        wcstombs(argument_utf8, argument, argument_size);

        error = irecv_send_command(client, argument_utf8);
        free(argument_utf8);

        DEBUG_LOG("%s\n", irecv_strerror(error));
        break;

    case EXEC_EXPLOIT:
        if (argument != NULL) {
            irecv_event_subscribe(client, IRECV_PROGRESS, &handle_progress_event, NULL);
            char* argument_utf8;
            size_t argument_size = wcstombs(NULL, argument, 0) + 1;
            argument_utf8 = (char*)malloc(argument_size);
            wcstombs(argument_utf8, argument, argument_size);

            error = irecv_send_file(client, argument_utf8, 0);
            free(argument_utf8);

            if (error != IRECV_E_SUCCESS) {
                DEBUG_LOG("%s\n", irecv_strerror(error));
                break;
            }
        }
        error = irecv_trigger_limera1n_exploit(client);
        DEBUG_LOG("%s\n", irecv_strerror(error));
        break;

    case LAUNCH_SHELL:
        start_shell(client);
        break;

    case EXEC_SCRIPT:
        load_file_to_buffer(argument, &buffer, &buffer_length);
        if (buffer) {
            buffer[buffer_length] = '\0';

            error = irecv_execute_script(client, buffer);
            if (error != IRECV_E_SUCCESS) {
                DEBUG_LOG("%s\n", irecv_strerror(error));
            }

            free(buffer);
        }
        else {
            fwprintf(stderr, L"Could not read file '%ls'\n", argument);
        }
        break;

    case DISPLAY_MODE:
        setbuf(stdout, NULL);

        irecv_get_mode(client, &mode);
        wprintf(L"MODE: %s\n", mode_to_string(mode));

        char* value = NULL;
        error = irecv_getenv(client, "build-version", &value);
        if (error != IRECV_E_SUCCESS) {
            DEBUG_LOG("%s\n", irecv_strerror(error));
        }
        wprintf(L"BUILD-VERSION: %S\n", value);

        char ecid[17];
        error = irecv_get_ecid_str(client, ecid);
        if (error != IRECV_E_SUCCESS) {
            DEBUG_LOG("%s\n", irecv_strerror(error));
        }
        wprintf(L"ECID: %S \n", ecid);

        break;

    case PRINT_SHELL_HEADER:
        setbuf(stdout, NULL);

        irecv_event_subscribe(client, IRECV_RECEIVED, &handle_received_event, NULL);

        error = irecv_receive(client);
        if (error != IRECV_E_SUCCESS) {
            DEBUG_LOG("%s\n", irecv_strerror(error));
        }
        break;

    case REBOOT_NORMAL_MODE:
        error = irecv_setenv(client, "auto-boot", "true");
        if (error != IRECV_E_SUCCESS) {
            DEBUG_LOG("%s\n", irecv_strerror(error));
            break;
        }

        error = irecv_saveenv(client);
        if (error != IRECV_E_SUCCESS) {
            DEBUG_LOG("%s\n", irecv_strerror(error));
            break;
        }

        error = irecv_reboot(client);
        if (error != IRECV_E_SUCCESS) {
            DEBUG_LOG("%s\n", irecv_strerror(error));
        }
        else {
            DEBUG_LOG("%s\n", irecv_strerror(error));
        }
        break;
    default:
        fwprintf(stderr, L"Unknown action\n");
        break;
    }

    irecv_close(client);

    return 0;
}
