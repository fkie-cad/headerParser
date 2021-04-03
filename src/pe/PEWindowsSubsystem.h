#ifndef HEADER_PARSER_PE_WINDOWS_SUBSYSTEM_H
#define HEADER_PARSER_PE_WINDOWS_SUBSYSTEM_H

typedef enum PEWinudowsSubsystem
{
    IMAGE_SUBSYSTEM_UNKNOWN = 0, // An unknown subsystem
    IMAGE_SUBSYSTEM_NATIVE = 1, // Device drivers and native Windows processes
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2, // The Windows graphical user interface (GUI) subsystem
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3, // The Windows character subsystem
    IMAGE_SUBSYSTEM_OS2_CUI = 5, // The OS/2 character subsystem
    IMAGE_SUBSYSTEM_POSIX_CUI = 7, // The Posix character subsystem
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8, // Native Win9x driver
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9, // Windows CE
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10, // An Extensible Firmware Interface (EFI) application
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11, // An EFI driver with boot services
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12, // An EFI driver with run-time services
    IMAGE_SUBSYSTEM_EFI_ROM = 13, // An EFI ROM image
    IMAGE_SUBSYSTEM_XBOX = 14, // XBOX
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16 // Windows boot application.
} PEWindowsSubsystem;

#endif
