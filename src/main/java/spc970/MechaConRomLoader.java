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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Pointer24DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

/** Loads raw 256 KiB Sony MechaCon ROM dumps into their SPC970 memory map. */
public final class MechaConRomLoader extends AbstractProgramWrapperLoader {

	public static final String LOADER_NAME = "Sony MechaCon ROM";

	static final long ROM_SIZE = 0x40000;
	static final long ROM_BASE = 0xfc0000;
	static final long ROM_END = 0xffffff;
	static final long INTERNAL_RAM_SIZE = 0x10000;
	static final long BANK_SIZE = 0x10000;
	private static final int BANK_COUNT = (int) (ROM_SIZE / BANK_SIZE);

	private static final long FAR_VECTOR_1_OFFSET = 0x3ff90;
	private static final long FAR_VECTOR_2_OFFSET = 0x3ff9c;
	private static final long RESET_VECTOR_OFFSET = 0x3fffe;
	private static final long LICENSE_SEARCH_OFFSET = 0x3b000;
	private static final int LICENSE_SEARCH_LENGTH = 0x400;
	private static final byte[] LICENSE_MARKER =
		"Licensed bySonyComputerEntertainmentof America(Europe)Inc."
			.getBytes(StandardCharsets.US_ASCII);
	private static final LanguageCompilerSpecPair LANGUAGE_COMPILER_SPEC =
		new LanguageCompilerSpecPair("spc970:LE:16:default", "default");

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!isMechaConRom(provider)) {
			return List.of();
		}
		return List.of(new LoadSpec(this, ROM_BASE, LANGUAGE_COMPILER_SPEC, true));
	}

	/**
	 * Uses independent structural signals so similarly-sized arbitrary binaries are not claimed.
	 */
	static boolean isMechaConRom(ByteProvider provider) throws IOException {
		if (provider.length() != ROM_SIZE) {
			return false;
		}

		return findPrimaryBankOffset(provider) >= 0 && containsLicenseMarker(provider);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		settings.monitor().setMessage("Loading Sony MechaCon ROM");
		settings.monitor().checkCancelled();

		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, settings.provider(),
			settings.monitor());
		try {
			createRomBanks(program, settings, fileBytes, ram);
		}
		catch (AddressOverflowException e) {
			throw new IOException("MechaCon ROM does not fit in the SPC970 address space", e);
		}

		MemoryBlock internalRam = MemoryBlockUtils.createUninitializedBlock(program, false,
			"INTERNAL_RAM", ram.getAddress(0), INTERNAL_RAM_SIZE, "Sony MechaCon internal RAM",
			LOADER_NAME, true, true, false, settings.log());
		if (internalRam == null) {
			throw new IOException("Could not create the MechaCon internal RAM memory block");
		}
	}

	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms,
			ImporterSettings settings) throws CancelledException, IOException {
		long primaryBankOffset = findPrimaryBankOffset(settings.provider());
		if (primaryBankOffset < 0) {
			throw new IOException("Could not locate the MechaCon primary ROM bank");
		}
		long primaryBankAddress = ROM_BASE + primaryBankOffset;
		int resetOffset = readUnsigned16(settings.provider(), RESET_VECTOR_OFFSET);
		long farTarget1 = readUnsigned24(settings.provider(), FAR_VECTOR_1_OFFSET);
		long farTarget2 = readUnsigned24(settings.provider(), FAR_VECTOR_2_OFFSET);

		for (Loaded<Program> loaded : loadedPrograms) {
			settings.monitor().checkCancelled();
			loaded.apply(program -> {
				int transaction =
					program.startTransaction("Apply Sony MechaCon memory profile");
				boolean commit = false;
				try {
					applyRegisterContext(program, settings.log());
					applyPlatformSymbols(program, settings);
					applyNonExecutableRomMarkers(program, settings);
					applyVectors(program, settings, primaryBankAddress, resetOffset, farTarget1,
						farTarget2);
					commit = true;
				}
				finally {
					program.endTransaction(transaction, commit);
				}
			});
		}
	}

	private static void createRomBanks(Program program, ImporterSettings settings,
			FileBytes fileBytes, AddressSpace ram) throws IOException, AddressOverflowException {
		for (int index = 0; index < BANK_COUNT; index++) {
			long fileOffset = index * BANK_SIZE;
			long bankAddress = ROM_BASE + fileOffset;
			String bankName = String.format("%02X", bankAddress >>> 16);
			long lastNonZero = findLastNonZero(settings.provider(), fileOffset, BANK_SIZE);
			if (lastNonZero < 0) {
				createRomBlock(program, settings, fileBytes, "RESERVED_" + bankName,
					ram.getAddress(bankAddress), fileOffset, BANK_SIZE,
					"Reserved, zero-filled MechaCon bank " + bankName, false);
				continue;
			}

			long executableLength = lastNonZero + 1;
			createRomBlock(program, settings, fileBytes, "ROM_" + bankName,
				ram.getAddress(bankAddress), fileOffset, executableLength,
				"Sony MechaCon firmware ROM bank " + bankName, true);
			if (executableLength < BANK_SIZE) {
				createRomBlock(program, settings, fileBytes, "PADDING_" + bankName,
					ram.getAddress(bankAddress + executableLength),
					fileOffset + executableLength, BANK_SIZE - executableLength,
					"Trailing zero padding in MechaCon bank " + bankName, false);
			}
		}
	}

	/**
	 * Records the direct-page value used throughout all known MechaCon firmware. The loader's
	 * structural checks keep this platform-specific invariant out of generic SPC970 programs.
	 */
	static void applyRegisterContext(Program program, MessageLog log) {
		Register dp = program.getProgramContext().getRegister("DP");
		if (dp == null) {
			log.appendMsg(LOADER_NAME, "SPC970 language does not define the DP register");
			return;
		}

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		try {
			program.getProgramContext().setValue(dp, space.getAddress(ROM_BASE),
				space.getAddress(ROM_END), BigInteger.ZERO);
		}
		catch (ContextChangeException e) {
			log.appendMsg(LOADER_NAME,
				"Could not apply the MechaCon DP=0 register context: " + e.getMessage());
		}
	}

	private static void createRomBlock(Program program, ImporterSettings settings,
			FileBytes fileBytes, String name, Address start, long fileOffset, long length,
			String comment, boolean execute) throws AddressOverflowException, IOException {
		MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, name, start,
			fileBytes, fileOffset, length, comment, LOADER_NAME, true, false, execute,
			settings.log());
		if (block == null) {
			throw new IOException("Could not create the MechaCon " + name + " memory block");
		}
	}

	private static void applyNonExecutableRomMarkers(Program program, ImporterSettings settings) {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.getName().startsWith("RESERVED_") &&
				!block.getName().startsWith("PADDING_")) {
				continue;
			}
			String label = block.getName().toLowerCase();
			try {
				program.getSymbolTable().createLabel(block.getStart(), label, SourceType.IMPORTED);
				program.getListing().setComment(block.getStart(), CommentType.PLATE,
					block.getComment() + "; not executable");
			}
			catch (InvalidInputException e) {
				settings.log().appendMsg(LOADER_NAME,
					"Could not label " + block.getName() + ": " + e.getMessage());
			}
		}
	}

	private static void applyPlatformSymbols(Program program, ImporterSettings settings) {
		SymbolTable symbols = program.getSymbolTable();
		int applied = 0;
		for (MechaConSymbols.Entry entry : MechaConSymbols.ENTRIES) {
			AddressSpace space = program.getAddressFactory().getAddressSpace(entry.addressSpace());
			if (space == null) {
				settings.log().appendMsg(LOADER_NAME,
					"Address space not found for symbol " + entry.name() + ": " +
						entry.addressSpace());
				continue;
			}
			Address address = space.getAddress(entry.offset());
			if (!program.getMemory().contains(address)) {
				settings.log().appendMsg(LOADER_NAME,
					"Memory is not mapped for symbol " + entry.name() + " at " + address);
				continue;
			}
			try {
				symbols.createLabel(address, entry.name(), SourceType.IMPORTED);
				applied++;
			}
			catch (InvalidInputException e) {
				settings.log().appendMsg(LOADER_NAME,
					"Could not create symbol " + entry.name() + " at " + address + ": " +
						e.getMessage());
			}
		}
		settings.log().appendMsg(LOADER_NAME, "Applied " + applied + " MechaCon symbols");
	}

	private static void applyVectors(Program program, ImporterSettings settings,
			long primaryBankAddress, int resetOffset, long farTarget1, long farTarget2) {
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		Address romStart = ram.getAddress(primaryBankAddress);
		markAsFunction(program, "rom_start", romStart);
		program.getSymbolTable().addExternalEntryPoint(romStart);

		if (resetOffset != 0 && resetOffset != 0xffff) {
			applyVector(program, settings, ram.getAddress(ROM_BASE + RESET_VECTOR_OFFSET),
				ram.getAddress(primaryBankAddress + resetOffset), "RESET_VECTOR", "reset", false);
		}
		else {
			settings.log().appendMsg(LOADER_NAME, "Reset vector is not present");
		}

		applyFarVectorIfPresent(program, settings, ram, FAR_VECTOR_1_OFFSET, farTarget1,
			"VECTOR_FFFF90", "vector_ffff90");
		applyFarVectorIfPresent(program, settings, ram, FAR_VECTOR_2_OFFSET, farTarget2,
			"VECTOR_FFFF9C", "vector_ffff9c");
	}

	private static void applyFarVectorIfPresent(Program program, ImporterSettings settings,
			AddressSpace ram, long vectorOffset, long target, String vectorName,
			String targetName) {
		if (isRomAddress(target)) {
			applyVector(program, settings, ram.getAddress(ROM_BASE + vectorOffset),
				ram.getAddress(target), vectorName, targetName, true);
		}
		else {
			settings.log().appendMsg(LOADER_NAME, vectorName + " is not present");
		}
	}

	private static void applyVector(Program program, ImporterSettings settings,
			Address vectorAddress, Address targetAddress, String vectorName, String targetName,
			boolean farPointer) {
		try {
			program.getSymbolTable().createLabel(vectorAddress, vectorName, SourceType.IMPORTED);
			if (program.getListing().getDefinedDataAt(vectorAddress) == null) {
				program.getListing().createData(vectorAddress,
					farPointer ? Pointer24DataType.dataType : WordDataType.dataType);
			}
			program.getReferenceManager().addMemoryReference(vectorAddress, targetAddress,
				RefType.DATA, SourceType.IMPORTED, 0);
			program.getListing().setComment(vectorAddress, CommentType.EOL,
				"Resolves to " + targetAddress);
			markAsFunction(program, targetName, targetAddress);
			program.getSymbolTable().addExternalEntryPoint(targetAddress);
		}
		catch (InvalidInputException | CodeUnitInsertionException e) {
			settings.log().appendMsg(LOADER_NAME,
				"Could not apply vector " + vectorName + " at " + vectorAddress + ": " +
					e.getMessage());
		}
	}

	private static boolean matches(ByteProvider provider, long offset, int... expected)
			throws IOException {
		for (int i = 0; i < expected.length; i++) {
			if (Byte.toUnsignedInt(provider.readByte(offset + i)) != expected[i]) {
				return false;
			}
		}
		return true;
	}

	private static boolean containsLicenseMarker(ByteProvider provider) throws IOException {
		byte[] window = provider.readBytes(LICENSE_SEARCH_OFFSET, LICENSE_SEARCH_LENGTH);
		for (int start = 0; start <= window.length - LICENSE_MARKER.length; start++) {
			int index = 0;
			while (index < LICENSE_MARKER.length &&
					window[start + index] == LICENSE_MARKER[index]) {
				index++;
			}
			if (index == LICENSE_MARKER.length) {
				return true;
			}
		}
		return false;
	}

	static long findPrimaryBankOffset(ByteProvider provider) throws IOException {
		if (provider.length() != ROM_SIZE) {
			return -1;
		}
		for (int index = 0; index < BANK_COUNT; index++) {
			long bankOffset = index * BANK_SIZE;
			if (startupMatches(provider, bankOffset)) {
				return bankOffset;
			}
		}
		return -1;
	}

	private static boolean startupMatches(ByteProvider provider, long bankOffset)
			throws IOException {
		return matches(provider, bankOffset, 0xe6, 0x00, 0xd8, 0xe8) &&
			matches(provider, bankOffset + 0x05, 0x09, 0x36, 0xcc, 0x06, 0x0a, 0xd8, 0xe8) &&
			matches(provider, bankOffset + 0x0d, 0x09, 0xea, 0x00, 0x01, 0xe8) &&
			matches(provider, bankOffset + 0x13, 0x09, 0xe8) &&
			matches(provider, bankOffset + 0x16, 0x09, 0xcc, 0x07, 0x04, 0xec) &&
			(matches(provider, bankOffset + 0x1c, 0xe5, 0xff, 0xe2, 0x80) ||
				matches(provider, bankOffset + 0x1c, 0xe6, 0xff, 0xe2, 0x80));
	}

	private static long findLastNonZero(ByteProvider provider, long offset, long length)
			throws IOException {
		byte[] bytes = provider.readBytes(offset, length);
		for (int index = bytes.length - 1; index >= 0; index--) {
			if (bytes[index] != 0) {
				return index;
			}
		}
		return -1;
	}

	private static int readUnsigned16(ByteProvider provider, long offset) throws IOException {
		return Byte.toUnsignedInt(provider.readByte(offset)) |
			(Byte.toUnsignedInt(provider.readByte(offset + 1)) << 8);
	}

	private static long readUnsigned24(ByteProvider provider, long offset) throws IOException {
		return Byte.toUnsignedLong(provider.readByte(offset)) |
			(Byte.toUnsignedLong(provider.readByte(offset + 1)) << 8) |
			(Byte.toUnsignedLong(provider.readByte(offset + 2)) << 16);
	}

	private static boolean isRomAddress(long address) {
		return address >= ROM_BASE && address <= ROM_END;
	}
}
