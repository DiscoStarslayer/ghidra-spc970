# Ghidra SPC970 processor module

This extension adds Sony SPC970 support to Ghidra, and MechaCon firmware dump loader.

## Compatibility

The extension builds and loads with Ghidra 12.1.3. Ghidra extensions are release-specific, so build a new archive against each Ghidra version you intend to use.

Ghidra 12.1.3 requires JDK 21 or later and Gradle 8.5 or later. The Gradle wrapper shipped in a public Ghidra distribution can be used without installing Gradle separately.

## Build

Set `GHIDRA_INSTALL_DIR` to the root of an unpacked Ghidra release, then invoke Gradle from this repository:

```sh
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra_12.1.3_PUBLIC
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" -p . clean buildExtension
```

## Install and use

In Ghidra, choose **File > Install Extensions...**, add the generated ZIP, enable **SPC970**, and restart Ghidra when prompted.

For a recognized 256 KiB MechaCon dump, choose **Sony MechaCon ROM** in the import
dialog. The loader automatically:

- selects `spc970:LE:16:default`;
- maps the four 64 KiB ROM banks
- locates the active firmware bank (`FC` in version 2 and `FD` in version 3)
- maps SRAM
- applies hardware, command, MG and buffer symbols
- creates entry points

Mechacon analyzer discovers SCMD, NCMD, PMAP, and MG dispatch tables. It identifies known SFR helper routines and MG S-box data.

## Development

`data/buildLanguage.xml` remains available for the GhidraDev/Eclipse workflow. GhidraDev generates the local `.antProperties.xml` file when the project is linked to a Ghidra installation; that machine-specific file is intentionally not tracked.

