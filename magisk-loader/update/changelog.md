To celebrate the release of Android 16, we are excited to announce a new stable version of LSPosed!

For the past few months, I have been focused on finishing my PhD thesis manuscript, which has limited my active development on LSPosed. I sincerely appreciate the community's passion and support during this time. It has been a pleasure to witness our community grow and thrive. Your trust and respect have been invaluable, helping me navigate the challenges of being a PhD candidate.

While maintaining this project is a joyful responsibility, my academic commitments to research and teaching also call for my attention. The current codebase of LSPosed is stable and robust. For those eager for new features, I encourage you to get involved! Developers are welcome to contribute to the project, and all users can participate in the [Discussions](https://github.com/JingMatrix/LSPosed/discussions) to share experiences and tips. A vibrant community is the most valuable asset for any open-source project.

To better understand LSPosed, we recommend reading our [troubleshooting guide](https://github.com/JingMatrix/LSPosed/issues/123).

### What's New
*   Full support for Android 16.
*   Hide traces introduced by the `dex2oat` hook.
*   The LSPosed manager can now be opened via the Action button.
*   New options have been added to the `Select` menu for scopes.
*   Allow users to disable detectable logging of LSPosed.

### Bug Fixes
*   The `LSPlt` hook has been abandoned for efficiency considerations.
*   Resolved an issue where modules targeting `systemui` (e.g., `ClassicPowerMenu`) were not working.
*   Removed Telemetry monitoring.

### Other Changes
*   The dependency on `topjohnwu/libcxx` has been removed in favor of the official C++ implementation. This will result in a larger release archive for LSPosed.

### Development Priorities
*   Creating comprehensive development documentation for LSPosed.
*   Resolving open issues with assignees.

**Full Changelog**: [v1.10.1...v1.10.2](https://github.com/JingMatrix/LSPosed/compare/v1.10.1...v1.10.2)
