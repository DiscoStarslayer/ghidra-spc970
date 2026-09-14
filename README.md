# Ghidra SPC970 processor module

This extension adds Sony SPC970 support to Ghidra.

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

The module does not claim a container file format. Import firmware as **Raw Binary**, then select the language ID `spc970:LE:16:default` and set the image base appropriate for the target firmware.

## Development

`data/buildLanguage.xml` remains available for the GhidraDev/Eclipse workflow. GhidraDev generates the local `.antProperties.xml` file when the project is linked to a Ghidra installation; that machine-specific file is intentionally not tracked.
