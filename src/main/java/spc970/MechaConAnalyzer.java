/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package spc970;

import java.nio.charset.StandardCharsets;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Conservatively discovers MechaCon firmware tables and creates analysis-derived markup.
 * Existing code, data, symbols, comments, and references are never removed.
 */
public final class MechaConAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Sony MechaCon Firmware";
	private static final String DESCRIPTION =
		"Finds validated MechaCon command tables, handler functions, and firmware metadata.";
	private static final String MARKUP_VERSION_OPTION = "MechaCon Markup Version";
	private static final int MARKUP_VERSION = 3;
	private static final String LANGUAGE_ID = "spc970:LE:16:default";

	private static final byte[] LICENSE_MARKER = ascii(
		"Licensed bySonyComputerEntertainmentof America(Europe)Inc.");
	private static final byte[] SFR_WRITE_BYTE_SIGNATURE = bytes(
		0xe6, 0x00, 0xf3, 0xda, 0xf8, 0x04, 0xc8, 0xef, 0xf3, 0xdd, 0xfd, 0xa6, 0x08);
	private static final byte[] SCMD_DISPATCH_SIGNATURE =
		bytes(0xe6, 0x0c, 0xf3, 0xda, 0xf8, 0x0c, 0x6b, 0x12, 0x00);
	private static final byte[] UART_DIAGNOSTIC_SIGNATURE =
		bytes(0xf3, 0xda, 0xf8, 0x04, 0xec, 0xf8, 0x00, 0xff);
	private static final byte[] MAGIC_GATE_SBOX_SIGNATURE =
		bytes(0x0e, 0x00, 0x04, 0x0f, 0x0d, 0x07, 0x01, 0x04, 0x02, 0x0e, 0x0f, 0x02);
	private static final byte[] MAGIC_GATE_CODE_SIGNATURE =
		bytes(0xe6, 0x02, 0xf8, 0x0c, 0x6b, 0x00, 0x01, 0xec);

	public MechaConAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		// Reserve validated firmware tables and constant blobs before recursive disassembly can
		// misinterpret their high-entropy contents as code.
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return LANGUAGE_ID.equals(program.getLanguageID().toString()) && isMechaConProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		MechaConRomLoader.applyRegisterContext(program, log);

		Options programInfo = program.getOptions(Program.PROGRAM_INFO);
		if (programInfo.getInt(MARKUP_VERSION_OPTION, 0) >= MARKUP_VERSION) {
			return true;
		}

		monitor.setMessage("Analyzing Sony MechaCon firmware");
		try {
			RomImage image = new RomImage(program);
			long primaryBank = image.findPrimaryBank();
			if (primaryBank < 0) {
				log.appendMsg(NAME, "Could not identify the primary MechaCon ROM bank");
				return false;
			}
			Markup markup = new Markup(program, image, primaryBank, monitor, log);
			markup.apply();
			programInfo.setInt(MARKUP_VERSION_OPTION, MARKUP_VERSION);
			log.appendMsg(NAME, markup.summary());
			return true;
		}
		catch (MemoryAccessException | CodeUnitInsertionException e) {
			log.appendMsg(NAME, "Markup stopped without removing existing program information: " +
				e.getMessage());
			return false;
		}
	}

	private static boolean isMechaConProgram(Program program) {
		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		try {
			if (!isInitialized(memory, space.getAddress(MechaConRomLoader.ROM_BASE),
				MechaConRomLoader.ROM_END)) {
				return false;
			}
			RomImage image = new RomImage(program);
			return image.findPrimaryBank() >= 0 &&
				image.find(LICENSE_MARKER, MechaConRomLoader.ROM_BASE + 0x3b000,
					MechaConRomLoader.ROM_BASE + 0x3b400) >= 0;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	private static boolean isInitialized(Memory memory, Address start, long endOffset) {
		long current = start.getOffset();
		while (current <= endOffset) {
			MemoryBlock block = memory.getBlock(start.getAddressSpace().getAddress(current));
			if (block == null || !block.isInitialized()) {
				return false;
			}
			current = block.getEnd().getOffset() + 1;
		}
		return true;
	}

	private static final class Markup {

		private final Program program;
		private final RomImage image;
		private final long primaryBank;
		private final TaskMonitor monitor;
		private final MessageLog log;
		private final Memory memory;
		private final Listing listing;
		private final AddressSpace space;
		private final AddressSet codeTargets = new AddressSet();

		private int scmdCount;
		private int ncmdDiagnosticCount;
		private int pmapCount;
		private int magicGateCount;
		private int magicGateConstantBytes;
		private boolean pmapPresent;

		Markup(Program program, RomImage image, long primaryBank, TaskMonitor monitor,
				MessageLog log) {
			this.program = program;
			this.image = image;
			this.primaryBank = primaryBank;
			this.monitor = monitor;
			this.log = log;
			memory = program.getMemory();
			listing = program.getListing();
			space = program.getAddressFactory().getDefaultAddressSpace();
		}

		void apply() throws CancelledException, CodeUnitInsertionException {
			markKnownSignatures();
			markKnownData();

			DispatchTable scmd = findScmdSubcommandTable();
			if (scmd != null) {
				markScmdTables(scmd);
			}
			else {
				log.appendMsg(NAME, "SCMD subcommand table was not found");
			}

			DispatchTable pmap = findPmapTable();
			if (pmap != null) {
				pmapPresent = true;
				markPmapTable(pmap);
			}
			else {
				log.appendMsg(NAME,
					"PMAP table is absent; this is normal for MechaCon variants without an optical drive");
			}

			DispatchTable magicGate = findMagicGateTable();
			if (magicGate != null) {
				markMagicGateTable(magicGate);
			}
			else {
				log.appendMsg(NAME, "MagicGate table was not found");
			}

			markFirmwareMetadata();
			disassembleHandlers();
		}

		String summary() {
			String pmap = pmapPresent ? Integer.toString(pmapCount) : "absent";
			return "Applied conservative markup: SCMD=" + scmdCount +
				", NCMD diagnostic=" + ncmdDiagnosticCount + ", PMAP=" + pmap +
				", MagicGate=" + magicGateCount + ", MagicGate constants=" +
				magicGateConstantBytes + " bytes, handler targets=" +
				codeTargets.getNumAddresses();
		}

		private void markKnownSignatures() throws CancelledException {
			long sfr = image.find(SFR_WRITE_BYTE_SIGNATURE, MechaConRomLoader.ROM_BASE,
				MechaConRomLoader.ROM_END);
			if (sfr >= 0) {
				markCodeTarget(sfr, "SFR_WriteByte");
				markCodeTarget(sfr + 0x14, "SFR_ReadByte");
				markCodeTarget(sfr + 0x68, "SFR_WriteDword");
				markCodeTarget(sfr + 0xb6, "SFR_ReadDword");
				markCodeTarget(sfr + 0x16c, "SFR_SetBit");
				markCodeTarget(sfr + 0x1a9, "SFR_ClearBit");
			}

			long scmdDispatcher = image.find(SCMD_DISPATCH_SIGNATURE,
				primaryBank, primaryBank + MechaConRomLoader.BANK_SIZE);
			if (scmdDispatcher >= 0) {
				markCodeTarget(scmdDispatcher, "SCMD_Command_Dispatcher");
			}

			long uart = image.find(UART_DIAGNOSTIC_SIGNATURE,
				MechaConRomLoader.ROM_BASE + 0x30000, MechaConRomLoader.ROM_END);
			if (uart >= 0) {
				markCodeTarget(uart, "UART_Main_Diagnostic_Loop");
			}
		}

		private void markKnownData() throws CancelledException, CodeUnitInsertionException {
			long sbox = image.find(MAGIC_GATE_SBOX_SIGNATURE, primaryBank,
				primaryBank + 0x8000);
			if (sbox >= 0) {
				createAnalysisLabel(sbox, "MG_Cipher_SBox_Tables");
				setPlateCommentIfAbsent(sbox,
					"MagicGate cipher substitution tables (8 tables x 64 bytes)");
				createDataIfUndefined(sbox,
					new ArrayDataType(ByteDataType.dataType, 512, 1));
			}
		}

		private DispatchTable findScmdSubcommandTable() throws CancelledException {
			long end = primaryBank + MechaConRomLoader.BANK_SIZE - 24;
			for (long address = primaryBank; address < end; address++) {
				monitor.checkCancelled();
				if (image.u8(address + 4) == 0x00 && image.u8(address + 5) == 0x01 &&
					image.u8(address + 10) == 0x01 && image.u8(address + 11) == 0x01 &&
					image.u8(address + 16) == 0x10 && image.u8(address + 22) == 0x11 &&
					image.isRomPointer(image.u32(address)) &&
					image.isRomPointer(image.u32(address + 6))) {
					int count = countPointerFirstEntries(address, 128);
					if (count >= 40) {
						return new DispatchTable(address, count);
					}
				}
			}
			return null;
		}

		private void markScmdTables(DispatchTable scmd)
				throws CancelledException, CodeUnitInsertionException {
			scmdCount = scmd.count();
			createAnalysisLabel(scmd.address(), "LUT_SCMD_03_Subcommands");
			setPlateCommentIfAbsent(scmd.address(),
				"SCMD 03 subcommands: 32-bit stored handler, command ID, parameter count");
			createDataIfUndefined(scmd.address(), pointerFirstEntryArray(scmd.count(),
				"MechaCon_SCMD03_Entry_v1"));
			for (int i = 0; i < scmd.count(); i++) {
				monitor.checkCancelled();
				long entry = scmd.address() + i * 6L;
				int command = image.u8(entry + 4);
				markPointerTarget(entry, image.u32(entry),
					String.format("SCMD_03_Subcmd_%02X_Handler", command));
			}

			DispatchTable main = findPointerTableEndingAt(scmd.address(), 29, 40);
			if (main != null) {
				markScmdMainTable(main);
				markNcmdTables(main.address());
			}

			long diagnosticStart = scmd.address() + scmd.count() * 6L;
			int diagnosticEntries = countPointerFirstEntries(diagnosticStart, 128);
			if (diagnosticEntries >= 60) {
				DispatchTable diagnostic =
					new DispatchTable(diagnosticStart, diagnosticEntries);
				markNcmdDiagnosticTable(diagnostic);
			}
		}

		private DispatchTable findPointerTableEndingAt(long end, int minimum, int maximum) {
			for (int count = maximum; count >= minimum; count--) {
				long start = end - count * 4L;
				boolean valid = true;
				for (int i = 0; i < count; i++) {
					if (!image.isRomPointer(image.u32(start + i * 4L))) {
						valid = false;
						break;
					}
				}
				if (valid) {
					return new DispatchTable(start, count);
				}
			}
			return null;
		}

		private void markScmdMainTable(DispatchTable table)
				throws CancelledException, CodeUnitInsertionException {
			createAnalysisLabel(table.address(), "LUT_SCMD_Main_Commands");
			setPlateCommentIfAbsent(table.address(),
				"SCMD handler pointers: commands 00-1c followed by supported 40-43 commands");
			createDataIfUndefined(table.address(),
				new ArrayDataType(Pointer32DataType.dataType, table.count(), 4));
			for (int i = 0; i < table.count(); i++) {
				monitor.checkCancelled();
				long pointerAddress = table.address() + i * 4L;
				int command = i < MechaConCommandNames.SCMD_LOW.length ? i :
					0x40 + i - MechaConCommandNames.SCMD_LOW.length;
				String commandName = scmdName(command);
				markPointerTarget(pointerAddress, image.u32(pointerAddress),
					String.format("SCMD_%02X_%s", command, commandName));
			}
		}

		private void markNcmdTables(long end)
				throws CancelledException, CodeUnitInsertionException {
			long start = end;
			int total = 0;
			while (total < 40 && start >= primaryBank + 6 &&
					image.isRomPointer(image.u32(start - 6))) {
				start -= 6;
				total++;
			}
			if (total < 24 || (total & 1) != 0) {
				return;
			}

			int count = total / 2;
			DataType type = ncmdEntryArray(count);
			createAnalysisLabel(start, "LUT_NCMD_Table_0");
			setPlateCommentIfAbsent(start,
				"NCMD table 0: 32-bit stored handler, flags, parameter count");
			createDataIfUndefined(start, type);

			long normalStart = start + count * 6L;
			createAnalysisLabel(normalStart, "LUT_NCMD_Table_1");
			setPlateCommentIfAbsent(normalStart,
				"NCMD table 1: 32-bit stored handler, flags, parameter count");
			createDataIfUndefined(normalStart, ncmdEntryArray(count));

			for (int tableIndex = 0; tableIndex < 2; tableIndex++) {
				long tableStart = start + tableIndex * count * 6L;
				for (int i = 0; i < count; i++) {
					monitor.checkCancelled();
					long entry = tableStart + i * 6L;
					String name = tableIndex == 1 && i < MechaConCommandNames.NCMD.length ?
						String.format("NCMD_%02X_%s", i, MechaConCommandNames.NCMD[i]) :
						String.format("NCMD_Table%d_%02X_Handler", tableIndex, i);
					markPointerTarget(entry, image.u32(entry), name);
				}
			}
		}

		private void markNcmdDiagnosticTable(DispatchTable table)
				throws CancelledException, CodeUnitInsertionException {
			ncmdDiagnosticCount = table.count();
			createAnalysisLabel(table.address(), "LUT_NCMD_0B_Subcommands");
			setPlateCommentIfAbsent(table.address(),
				"NCMD 0b diagnostic subcommands: 32-bit stored handler, command ID, parameter count");
			createDataIfUndefined(table.address(), pointerFirstEntryArray(table.count(),
				"MechaCon_NCMD0B_Entry_v1"));
			for (int i = 0; i < table.count(); i++) {
				monitor.checkCancelled();
				long entry = table.address() + i * 6L;
				int command = image.u8(entry + 4);
				markPointerTarget(entry, image.u32(entry),
					String.format("NCMD_0B_Subcmd_%02X_Handler", command));
			}
		}

		private DispatchTable findPmapTable() throws CancelledException {
			long searchStart = MechaConRomLoader.ROM_BASE + 0x30000;
			long searchEnd = MechaConRomLoader.ROM_END - 30;
			for (long address = searchStart; address < searchEnd; address++) {
				monitor.checkCancelled();
				if (image.u8(address) == 0x14 && image.u8(address + 6) == 0x15 &&
					image.u8(address + 12) == 0x16 && image.u8(address + 18) == 0x17 &&
					image.u8(address + 24) == 0x18 &&
					image.isRomPointer(image.u32(address + 2)) &&
					image.isRomPointer(image.u32(address + 8))) {
					long start = address;
					while (start >= searchStart + 6 &&
						image.isRomPointer(image.u32(start - 4)) &&
						image.u8(start - 6) < image.u8(start)) {
						start -= 6;
					}
					int count = countIdFirstEntries(start, 256);
					if (count >= 100) {
						return new DispatchTable(start, count);
					}
				}
			}
			return null;
		}

		private void markPmapTable(DispatchTable table)
				throws CancelledException, CodeUnitInsertionException {
			pmapCount = table.count();
			createAnalysisLabel(table.address(), "LUT_PMAP_Commands");
			setPlateCommentIfAbsent(table.address(),
				"PMAP optical-drive commands: command ID, parameter count, 32-bit stored handler");
			createDataIfUndefined(table.address(), idFirstEntryArray(table.count()));
			for (int i = 0; i < table.count(); i++) {
				monitor.checkCancelled();
				long entry = table.address() + i * 6L;
				int command = image.u8(entry);
				String commandName = MechaConCommandNames.PMAP.get(command);
				String label = commandName == null ?
					String.format("PMAP_%02X_Handler", command) :
					String.format("PMAP_%02X_%s", command, commandName);
				markPointerTarget(entry + 2, image.u32(entry + 2), label);
			}
		}

		private DispatchTable findMagicGateTable() throws CancelledException {
			long start = primaryBank + 0x2000;
			long end = primaryBank + 0x4000 - 128;
			for (long address = start; address < end; address += 2) {
				monitor.checkCancelled();
				boolean valid = true;
				for (int i = 0; i < MechaConCommandNames.MAGIC_GATE.length; i++) {
					long pointer = image.u32(address + i * 4L);
					int offset = (int) pointer & 0xffff;
					if (!image.isRomPointer(pointer) || offset < 0x1000 || offset > 0x6000) {
						valid = false;
						break;
					}
				}
				if (valid) {
					return new DispatchTable(address, MechaConCommandNames.MAGIC_GATE.length);
				}
			}
			return null;
		}

		private void markMagicGateTable(DispatchTable table)
				throws CancelledException, CodeUnitInsertionException {
			magicGateCount = table.count();
			createAnalysisLabel(table.address(), "LUT_SCMD_MagicGate");
			setPlateCommentIfAbsent(table.address(),
				"MagicGate SCMD handlers for commands 80-9f");
			createDataIfUndefined(table.address(),
				new ArrayDataType(Pointer32DataType.dataType, table.count(), 4));

			long constantsStart = table.address() + table.count() * 4L;
			long codeStart = image.find(MAGIC_GATE_CODE_SIGNATURE, constantsStart,
				Math.min(constantsStart + 0x400, primaryBank + MechaConRomLoader.BANK_SIZE));
			if (codeStart > constantsStart) {
				magicGateConstantBytes = (int) (codeStart - constantsStart);
				createAnalysisLabel(constantsStart, "MG_Cipher_Constants");
				setPlateCommentIfAbsent(constantsStart,
					"MagicGate cipher constants and lookup data");
				createDataIfUndefined(constantsStart,
					new ArrayDataType(ByteDataType.dataType, magicGateConstantBytes, 1));
				markCodeTarget(codeStart, "MagicGate_Cipher_Routines");
			}
			for (int i = 0; i < table.count(); i++) {
				monitor.checkCancelled();
				long pointerAddress = table.address() + i * 4L;
				markPointerTarget(pointerAddress, image.u32(pointerAddress),
					String.format("SCMD_MG_%02X_%s", 0x80 + i,
						MechaConCommandNames.MAGIC_GATE[i]));
			}
		}

		private int countPointerFirstEntries(long start, int maximum) {
			int count = 0;
			int previousId = -1;
			while (count < maximum && start + (count + 1L) * 6 <= MechaConRomLoader.ROM_END + 1) {
				long entry = start + count * 6L;
				int command = image.u8(entry + 4);
				if (!image.isRomPointer(image.u32(entry)) || command <= previousId) {
					break;
				}
				previousId = command;
				count++;
			}
			return count;
		}

		private int countIdFirstEntries(long start, int maximum) {
			int count = 0;
			int previousId = -1;
			while (count < maximum && start + (count + 1L) * 6 <= MechaConRomLoader.ROM_END + 1) {
				long entry = start + count * 6L;
				int command = image.u8(entry);
				if (!image.isRomPointer(image.u32(entry + 2)) || command <= previousId) {
					break;
				}
				previousId = command;
				count++;
			}
			return count;
		}

		private String scmdName(int command) {
			if (command < MechaConCommandNames.SCMD_LOW.length) {
				return MechaConCommandNames.SCMD_LOW[command];
			}
			int configIndex = command - 0x40;
			if (configIndex >= 0 && configIndex < MechaConCommandNames.SCMD_CONFIG.length) {
				return MechaConCommandNames.SCMD_CONFIG[configIndex];
			}
			return "Handler";
		}

		private DataType pointerFirstEntryArray(int count, String name) {
			StructureDataType entry = new StructureDataType(name, 0);
			entry.add(Pointer32DataType.dataType, 4, "handler", "Stored 32-bit code pointer");
			entry.add(ByteDataType.dataType, 1, "command", "Command or subcommand ID");
			entry.add(ByteDataType.dataType, 1, "parameterCount", "Expected parameter count");
			return new ArrayDataType(entry, count, 6);
		}

		private DataType idFirstEntryArray(int count) {
			StructureDataType entry = new StructureDataType("MechaCon_PMAP_Entry_v1", 0);
			entry.add(ByteDataType.dataType, 1, "command", "PMAP command ID");
			entry.add(ByteDataType.dataType, 1, "parameterCount", "Expected parameter count");
			entry.add(Pointer32DataType.dataType, 4, "handler", "Stored 32-bit code pointer");
			return new ArrayDataType(entry, count, 6);
		}

		private DataType ncmdEntryArray(int count) {
			StructureDataType entry = new StructureDataType("MechaCon_NCMD_Entry_v1", 0);
			entry.add(Pointer32DataType.dataType, 4, "handler", "Stored 32-bit code pointer");
			entry.add(ByteDataType.dataType, 1, "flags", "Command flags");
			entry.add(ByteDataType.dataType, 1, "parameterCount", "Expected parameter count");
			return new ArrayDataType(entry, count, 6);
		}

		private void markFirmwareMetadata()
				throws CancelledException, CodeUnitInsertionException {
			markFixedAscii(LICENSE_MARKER, "PS1_SCEx_License_String",
				MechaConRomLoader.ROM_BASE + 0x3b000, MechaConRomLoader.ROM_END);

			markRcsString("$Date:", "Firmware_Build_Date");
			markRcsString("$Author:", "Firmware_Build_Author");

			byte[] silicon = ascii("CXD2940QCXD2940QCXD2940Q");
			long siliconAddress = image.find(silicon, MechaConRomLoader.ROM_BASE + 0x30000,
				MechaConRomLoader.ROM_END);
			if (siliconAddress >= 0) {
				createAnalysisLabel(siliconAddress, "HW_MechaCon_Silicon_Revision");
				createDataIfUndefined(siliconAddress,
					StringDataType.dataType, silicon.length);
				long regionAddress = image.findBackward(ascii("for "), siliconAddress - 1,
					Math.max(MechaConRomLoader.ROM_BASE + 0x30000, siliconAddress - 20));
				if (regionAddress >= 0) {
					createAnalysisLabel(regionAddress, "HW_Target_Region");
					createDataIfUndefined(regionAddress, StringDataType.dataType,
						(int) (siliconAddress - regionAddress));
				}
			}

			long videoTs = image.find(ascii("VIDEO_TS"), primaryBank,
				primaryBank + MechaConRomLoader.BANK_SIZE);
			if (videoTs >= 0) {
				createAnalysisLabel(videoTs, "ROM_Default_DVD_Directory");
				createDataIfUndefined(videoTs, StringDataType.dataType, 9);
			}
		}

		private void markRcsString(String prefix, String label)
				throws CancelledException, CodeUnitInsertionException {
			long address = image.find(ascii(prefix), MechaConRomLoader.ROM_BASE + 0x30000,
				MechaConRomLoader.ROM_END);
			if (address < 0) {
				return;
			}
			int length = 1;
			while (address + length <= MechaConRomLoader.ROM_END &&
					image.u8(address + length) != '$') {
				length++;
			}
			if (address + length <= MechaConRomLoader.ROM_END) {
				length++;
			}
			createAnalysisLabel(address, label);
			createDataIfUndefined(address, StringDataType.dataType, length);
		}

		private void markFixedAscii(byte[] value, String label, long start, long end)
				throws CancelledException, CodeUnitInsertionException {
			long address = image.find(value, start, end);
			if (address >= 0) {
				createAnalysisLabel(address, label);
				createDataIfUndefined(address, StringDataType.dataType, value.length);
			}
		}

		private void markPointerTarget(long pointerAddress, long target, String label) {
			if (!image.isRomPointer(target)) {
				return;
			}
			Address sourceAddress = address(pointerAddress);
			Address targetAddress = address(target);
			if (program.getReferenceManager().getReference(sourceAddress, targetAddress, 0) == null) {
				program.getReferenceManager().addMemoryReference(sourceAddress, targetAddress,
					RefType.DATA, SourceType.ANALYSIS, 0);
			}
			markCodeTarget(target, label);
		}

		private void markCodeTarget(long target, String label) {
			if (!image.isRomPointer(target)) {
				return;
			}
			Address targetAddress = address(target);
			MemoryBlock block = memory.getBlock(targetAddress);
			if (block == null || !block.isExecute()) {
				return;
			}
			createAnalysisLabel(target, label);
			codeTargets.add(targetAddress);
		}

		private void createAnalysisLabel(long offset, String label) {
			Address target = address(offset);
			if (program.getSymbolTable().getGlobalSymbol(label, target) != null) {
				return;
			}
			try {
				program.getSymbolTable().createLabel(target, label, SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				log.appendMsg(NAME, "Could not create label " + label + " at " + target +
					": " + e.getMessage());
			}
		}

		private void setPlateCommentIfAbsent(long offset, String comment) {
			Address target = address(offset);
			if (listing.getComment(CommentType.PLATE, target) == null) {
				listing.setComment(target, CommentType.PLATE, comment);
			}
		}

		private void createDataIfUndefined(long offset, DataType type)
				throws CodeUnitInsertionException {
			createDataIfUndefined(offset, type, type.getLength());
		}

		private void createDataIfUndefined(long offset, DataType type, int length)
				throws CodeUnitInsertionException {
			Address start = address(offset);
			Address end = start.add(length - 1L);
			if (listing.isUndefined(start, end)) {
				listing.createData(start, type, length);
			}
		}

		private void disassembleHandlers() throws CancelledException {
			if (codeTargets.isEmpty()) {
				return;
			}
			DisassembleCommand disassemble =
				new DisassembleCommand(codeTargets, memory.getExecuteSet(), true);
			disassemble.applyTo(program, monitor);
			new CreateFunctionCmd(codeTargets, SourceType.ANALYSIS).applyTo(program, monitor);
		}

		private Address address(long offset) {
			return space.getAddress(offset);
		}
	}

	private record DispatchTable(long address, int count) {}

	private static final class RomImage {

		private final byte[] bytes = new byte[(int) MechaConRomLoader.ROM_SIZE];

		RomImage(Program program) throws MemoryAccessException {
			Memory memory = program.getMemory();
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			int copied = 0;
			while (copied < bytes.length) {
				Address address = space.getAddress(MechaConRomLoader.ROM_BASE + copied);
				MemoryBlock block = memory.getBlock(address);
				if (block == null || !block.isInitialized()) {
					throw new MemoryAccessException("ROM is not initialized at " + address);
				}
				int count = (int) Math.min(bytes.length - copied,
					block.getEnd().getOffset() - address.getOffset() + 1);
				int actual = memory.getBytes(address, bytes, copied, count);
				if (actual != count) {
					throw new MemoryAccessException("Short ROM read at " + address);
				}
				copied += actual;
			}
		}

		int u8(long address) {
			int offset = (int) (address - MechaConRomLoader.ROM_BASE);
			return offset >= 0 && offset < bytes.length ? Byte.toUnsignedInt(bytes[offset]) : -1;
		}

		long u32(long address) {
			int offset = (int) (address - MechaConRomLoader.ROM_BASE);
			if (offset < 0 || offset + 4 > bytes.length) {
				return -1;
			}
			return Byte.toUnsignedLong(bytes[offset]) |
				(Byte.toUnsignedLong(bytes[offset + 1]) << 8) |
				(Byte.toUnsignedLong(bytes[offset + 2]) << 16) |
				(Byte.toUnsignedLong(bytes[offset + 3]) << 24);
		}

		boolean isRomPointer(long pointer) {
			return pointer >= MechaConRomLoader.ROM_BASE &&
				pointer <= MechaConRomLoader.ROM_END;
		}

		long findPrimaryBank() {
			for (long bank = MechaConRomLoader.ROM_BASE;
					bank <= MechaConRomLoader.ROM_END;
					bank += MechaConRomLoader.BANK_SIZE) {
				if (matches((int) (bank - MechaConRomLoader.ROM_BASE),
					bytes(0xe6, 0x00, 0xd8, 0xe8)) &&
					matches((int) (bank - MechaConRomLoader.ROM_BASE + 0x05),
						bytes(0x09, 0x36, 0xcc, 0x06, 0x0a, 0xd8, 0xe8)) &&
					matches((int) (bank - MechaConRomLoader.ROM_BASE + 0x0d),
						bytes(0x09, 0xea, 0x00, 0x01, 0xe8)) &&
					matches((int) (bank - MechaConRomLoader.ROM_BASE + 0x13),
						bytes(0x09, 0xe8)) &&
					matches((int) (bank - MechaConRomLoader.ROM_BASE + 0x16),
						bytes(0x09, 0xcc, 0x07, 0x04, 0xec)) &&
					(matches((int) (bank - MechaConRomLoader.ROM_BASE + 0x1c),
						bytes(0xe5, 0xff, 0xe2, 0x80)) ||
						matches((int) (bank - MechaConRomLoader.ROM_BASE + 0x1c),
							bytes(0xe6, 0xff, 0xe2, 0x80)))) {
					return bank;
				}
			}
			return -1;
		}

		long find(byte[] pattern, long start, long end) {
			int first = Math.max(0, (int) (start - MechaConRomLoader.ROM_BASE));
			int last = Math.min(bytes.length - pattern.length,
				(int) (end - MechaConRomLoader.ROM_BASE));
			for (int offset = first; offset <= last; offset++) {
				if (matches(offset, pattern)) {
					return MechaConRomLoader.ROM_BASE + offset;
				}
			}
			return -1;
		}

		long findBackward(byte[] pattern, long start, long end) {
			int first = Math.min(bytes.length - pattern.length,
				(int) (start - MechaConRomLoader.ROM_BASE));
			int last = Math.max(0, (int) (end - MechaConRomLoader.ROM_BASE));
			for (int offset = first; offset >= last; offset--) {
				if (matches(offset, pattern)) {
					return MechaConRomLoader.ROM_BASE + offset;
				}
			}
			return -1;
		}

		private boolean matches(int offset, byte[] pattern) {
			for (int i = 0; i < pattern.length; i++) {
				if (bytes[offset + i] != pattern[i]) {
					return false;
				}
			}
			return true;
		}
	}

	private static byte[] ascii(String value) {
		return value.getBytes(StandardCharsets.US_ASCII);
	}

	private static byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			result[i] = (byte) values[i];
		}
		return result;
	}
}
