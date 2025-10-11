# WinOptimizer : Windows Optimizer & Cleaner

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Batch Script](https://img.shields.io/badge/Language-Batch-blue.svg)](#)
[![Windows 10](https://img.shields.io/badge/OS-Windows%2010-blue.svg)](#)
[![Windows 11](https://img.shields.io/badge/OS-Windows%2011-blue.svg)](#)

An advanced, command-line-based utility designed to clean, optimize, and enhance the performance of Windows 10 and 11 systems. This script provides a comprehensive suite of tools to remove junk files, tweak system and network settings, and manage system health, all from one easy-to-use interface.

## Features

-   **Administrator Check**: Ensures the script is run with the necessary privileges to perform system-level changes.
-   **Deep & Quick Cleaning**: Two cleaning modes to free up disk space by removing temporary files, logs, caches (including GPU and browser), prefetch files, and more.
--   **Performance Optimization Suite**: A one-click solution that applies a full range of optimizations for users who want maximum performance.
-   **Modular Tweaks**: Apply specific optimizations for Memory, CPU, Network, Visual Effects, and the Registry.
-   **System Health Checks**: Utilizes built-in Windows tools like `SFC`, `CHKDSK`, and `DISM` to verify system file integrity and disk health.
-   **System Status Overview**: Quickly view your current power plan, memory/CPU usage, and the status of key performance-related services.
-   **Full Reversibility**: A dedicated option to restore all settings to their default Windows configurations, ensuring you can safely revert any changes.
-   **User-Friendly Menu**: A clear and interactive command-line menu for easy navigation and operation.

## Getting Started

1.  **Download**: Download the `windows_optimizer.bat` script from this repository.
2.  **Run as Administrator**: Right-click on `windows_optimizer.bat` and select "Run as administrator". This is crucial as the script needs elevated permissions to modify system settings and clean protected files.
3.  **Navigate the Menu**: Use the number keys (1-11) to select an option from the main menu and press `Enter`.

## How to Use

After launching the script with administrator privileges, you will be presented with a main menu.

```
1. System Deep Clean (Logs, Temp, Cache, GPU)
2. Quick System Clean (Essential cleanup only)
3. Performance Optimization Suite [ADVANCED]
4. Memory & CPU Optimization
5. Network Performance Boost
6. Visual Effects Optimization
7. Registry Performance Tweaks
8. Restore All Settings to Default
9. System Health Check
10. View Current System Status
11. Exit
```

Simply type the number corresponding to the action you wish to perform and press `Enter`. For potentially impactful options like the "Performance Optimization Suite" and "Restore All Settings," you will be asked for confirmation before the script proceeds.

## Options Menu Explained

-   **1. System Deep Clean**: Performs an extensive cleanup, targeting a wide range of temporary and cached files across your system, including GPU caches, Windows error reports, and old installation files. Aims to free up a significant amount of disk space.

-   **2. Quick System Clean**: A faster, non-intrusive cleanup that targets the most common junk files like temporary folders and browser caches. Ideal for regular maintenance.

-   **3. Performance Optimization Suite \[ADVANCED]**: This is the all-in-one option. It runs a deep clean and then applies all the memory, CPU, network, visual, and registry optimizations, and activates the "Ultimate Performance" power plan. **Use this for the biggest performance boost.**

-   **4. Memory & CPU Optimization**: Tweaks settings to improve system responsiveness. This includes disabling memory-intensive services, optimizing virtual memory (page file), and adjusting CPU scheduling to prioritize active applications.

-   **5. Network Performance Boost**: Aims to reduce latency and improve network throughput by disabling bandwidth throttling, optimizing TCP settings, disabling Nagle's Algorithm, and setting DNS to a faster public provider (Google DNS).

-   **6. Visual Effects Optimization**: Disables non-essential animations and transparency effects. This can make the user interface feel snappier, especially on systems with weaker GPUs.

-   **7. Registry Performance Tweaks**: Applies various registry modifications to enhance performance, such as disabling file access timestamps, optimizing the file system cache, and turning off telemetry.

-   **8. Restore All Settings to Default**: **This is your safety net.** It will revert all changes made by this script back to the standard Windows settings, including services, power plans, and registry tweaks.

-   **9. System Health Check**: A diagnostic tool that runs `sfc /scannow` to check for corrupt system files, `chkdsk` to check the health of your drive, and `dism` to ensure the Windows image is healthy. It also initiates a quick malware scan and generates a system health report.

-   **10. View Current System Status**: Displays a quick overview of your current power plan, real-time memory and CPU usage, and the status of services commonly tweaked by optimizers.

## Disclaimer & Warning

-   **Backup Your Data**: While this script is designed to be safe, it is a powerful tool that makes significant changes to your system. It is **highly recommended** to back up your important data before using the advanced optimization features.
-   **Use at Your Own Risk**: The author is not responsible for any damage or data loss that may occur. Use this script at your own discretion.
-   **System Restore Point**: For maximum safety, consider creating a System Restore Point before running the "Performance Optimization Suite" or making significant registry changes.

## Future Development

-   [ ] Add support for cleaning more third-party application caches.
-   [ ] Implement a GUI version for less technical users.
-   [ ] Include options to manage startup programs directly from the script.
-   [ ] Add more granular control over which services to disable/enable.

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/10xrashed/windows_optimizer/issues) if you want to contribute.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Credits

*   **Original Author:** [10xrashed](https://github.com/10xrashed)
