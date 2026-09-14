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

import java.util.Map;

/** Protocol command names used by the MechaCon firmware analyzer. */
final class MechaConCommandNames {

	static final String[] SCMD_LOW = {
		"Nop", "GetParam", "GetSubq", "Test", "GetErrorLsn", "TrayControl",
		"ClearDspStickyRegister", "SoftReset", "ReadRtc", "WriteRtc", "ReadNvm",
		"WriteNvm", "SetHdMode", "SleepReq", "ResumeReq", "PowerOff", "ReadRtcEcr",
		"WriteRtcEcr", "ReadIlinkId", "WriteIlinkId", "CdCtrlAudioDigitalOut",
		"ForbidDvdPlayer", "AutoAdjustCtrl", "ReadModelNumber", "WriteModelNumber",
		"ForbidRead", "BootCertify", "CancelPowerOffReady", "BlueLedCtrl"
	};

	static final String[] SCMD_CONFIG = {
		"OpenConfig", "ReadConfig", "WriteConfig", "CloseConfig"
	};

	static final String[] NCMD = {
		"Nop", "Reset", "Standby", "Stop", "Pause", "SeekPause", "Read",
		"ReadCd", "ReadDvd", "ReadToc", "Diagnostic", "Test", "ReadKey",
		"ReadTocQ", "ReadXcd"
	};

	static final String[] MAGIC_GATE = {
		"Reset", "SessionInit", "WriteChallenge1", "WriteChallenge2", "ReadResponse1",
		"ReadResponse2", "WriteCardResponse", "VerifyCardResponse", "GetStatus",
		"Reserved89", "Reserved8a", "Reserved8b", "SetMode", "SetBlockSize",
		"ReadDataStream", "WriteDataStream", "KelfAuthInit", "KelfWriteHeader",
		"KelfVerify", "KelfReadStatus", "DiscAuthPhase1", "DiscAuthPhase2",
		"DiscAuthPhase3", "DiscAuthPhase4", "DiscAuthFinal", "Unknown99", "Unknown9a",
		"ExternalAuthInit", "ExternalAuthChallenge", "ExternalAuthResponse",
		"ExternalSetSize", "ExternalReadResult"
	};

	static final Map<Integer, String> PMAP = Map.ofEntries(
		Map.entry(0x10, "DiscModeCd8"),
		Map.entry(0x11, "DiscModeCd12"),
		Map.entry(0x12, "DiscModeDvdSingle8"),
		Map.entry(0x13, "DiscModeDvdDual8"),
		Map.entry(0x14, "DiscModeDvdSingle12"),
		Map.entry(0x15, "DiscModeDvdDual12"),
		Map.entry(0x16, "DiscDetect"),
		Map.entry(0x20, "LaserDiode"),
		Map.entry(0x22, "FocusUpDown"),
		Map.entry(0x23, "FocusAutoStart"),
		Map.entry(0x24, "FocusAutoStop"),
		Map.entry(0x25, "FocusSearchCheck"),
		Map.entry(0x30, "Tracking"),
		Map.entry(0x41, "SledControlMicro"),
		Map.entry(0x42, "SledControlBiphase"),
		Map.entry(0x43, "SledControlPosition"),
		Map.entry(0x44, "SledPositionHome"),
		Map.entry(0x45, "SledInSwitch"),
		Map.entry(0x50, "SpindleControl"),
		Map.entry(0x51, "SpindleClvS"),
		Map.entry(0x52, "SpindleClvA"),
		Map.entry(0x60, "Tray"),
		Map.entry(0x61, "TraySwitch"),
		Map.entry(0x8d, "ClearConfiguration"),
		Map.entry(0x8e, "UploadNew"),
		Map.entry(0x93, "UploadToRam"),
		Map.entry(0x97, "DetectAdjust"),
		Map.entry(0x99, "WriteChecksum"),
		Map.entry(0x9a, "ReadChecksum"),
		Map.entry(0x9b, "SetupOsd"),
		Map.entry(0x9e, "SetupSanyo"),
		Map.entry(0xa1, "AutoAdjustStage1"),
		Map.entry(0xa2, "AutoAdjustStage2"),
		Map.entry(0xa3, "AutoAdjustStage12"),
		Map.entry(0xa4, "AutoAdjustStage2Md"),
		Map.entry(0xa5, "AutoAdjustFixedGain"),
		Map.entry(0xa7, "RfDcLevel"),
		Map.entry(0xa8, "Tpp"),
		Map.entry(0xaa, "MirrorCheck"),
		Map.entry(0xab, "FocusErrorOffset"),
		Map.entry(0xb0, "CdPlay1"),
		Map.entry(0xb1, "CdPlay2"),
		Map.entry(0xb2, "CdPlay3"),
		Map.entry(0xb3, "CdPlay4"),
		Map.entry(0xb4, "CdStop"),
		Map.entry(0xb5, "CdPause"),
		Map.entry(0xb6, "CdTrackControl"),
		Map.entry(0xb8, "CdTrackLongControl"),
		Map.entry(0xb9, "CdPlay5"),
		Map.entry(0xc0, "DvdPlay1"),
		Map.entry(0xc1, "DvdPlay2"),
		Map.entry(0xc2, "DvdPlay3"),
		Map.entry(0xc3, "DvdStop"),
		Map.entry(0xc4, "DvdPause"),
		Map.entry(0xc5, "DvdTrackControl"),
		Map.entry(0xc7, "DvdTrackLongControl"),
		Map.entry(0xc8, "FocusJump"),
		Map.entry(0xca, "AdjustAutoTilt"),
		Map.entry(0xcb, "InitializeAutoTilt"),
		Map.entry(0xcd, "MoveAutoTilt"),
		Map.entry(0xd1, "SetDsp"),
		Map.entry(0xd3, "Gain"),
		Map.entry(0xde, "DspErrorRateControl"),
		Map.entry(0xdf, "DspErrorRate"),
		Map.entry(0xe0, "EepromWrite"),
		Map.entry(0xe1, "EepromRead"),
		Map.entry(0xe4, "RtcRead"),
		Map.entry(0xe5, "RtcWrite"),
		Map.entry(0xe6, "EcrRead"),
		Map.entry(0xe7, "EcrWrite"),
		Map.entry(0xe8, "CdError"),
		Map.entry(0xe9, "Jitter"),
		Map.entry(0xf2, "FocusJumpNew"),
		Map.entry(0xfc, "ReadModel2"),
		Map.entry(0xfd, "ReadModel"),
		Map.entry(0xfe, "EepromErase")
	);

	private MechaConCommandNames() {
	}
}
