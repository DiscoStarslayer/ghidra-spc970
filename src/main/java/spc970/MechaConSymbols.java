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

/** MechaCon platform symbols that should not be applied to generic SPC970 programs. */
final class MechaConSymbols {

	record Entry(String name, String addressSpace, long offset) {}

	static final Entry[] ENTRIES = {
		// Names verified in the established MechaCon reverse-engineering project.
		new Entry("auth_mode", "ram", 0x0009b6),
		new Entry("auth_b7", "ram", 0x0009b7),
		new Entry("auth_b8", "ram", 0x0009b8),
		new Entry("auth_status", "ram", 0x0009b9),
		new Entry("auth_keyslot", "ram", 0x0009ba),
		new Entry("auth_state", "ram", 0x0009ce),
		new Entry("scmd_ch_b_cmd", "ram", 0x001744),
		new Entry("scmd_ch_b_len", "ram", 0x001745),
		new Entry("scmd_ch_b_params", "ram", 0x001746),
		new Entry("scmd_in_cmd", "ram", 0x001756),
		new Entry("scmd_in_len", "ram", 0x001757),
		new Entry("scmd_in_params", "ram", 0x001758),
		new Entry("scmd_cmd", "ram", 0x00177c),
		new Entry("scmd_len", "ram", 0x00177d),
		new Entry("scmd_params", "ram", 0x00177e),

		// Additional names from the MechaCon platform profile.
		new Entry("Mech_Error_Flags", "ram", 0x000018),
		new Entry("DSP_Spindle_Speed_Mode", "ram", 0x000036),
		new Entry("Disc_Max_LBA", "ram", 0x000054),
		new Entry("HW_REG_TIME_MIN", "ram", 0x0000a5),
		new Entry("HW_REG_TIME_SEC", "ram", 0x0000a6),
		new Entry("HW_REG_TIME_FRAME", "ram", 0x0000a7),
		new Entry("HW_Drive_Current_Status", "ram", 0x000100),
		new Entry("HW_PORT_Syscon_Signal", "ram", 0x000101),
		new Entry("HW_PORT_Sensor_Switches", "ram", 0x000102),
		new Entry("HW_TestPin_Reg_bit4", "ram", 0x000107),
		new Entry("HW_TIMER_CONTROL", "ram", 0x0002b2),
		new Entry("HW_SIO_TX_BUFFER", "ram", 0x000300),
		new Entry("HW_SIO_RX_BUFFER", "ram", 0x000301),
		new Entry("Drive_Active_State", "ram", 0x000520),
		new Entry("HW_SLED_MOTOR_STATUS", "ram", 0x000608),
		new Entry("CDVD_Mode", "ram", 0x0009b6),
		new Entry("Mecha_ErrorCode", "ram", 0x0009b9),
		new Entry("MG_CardKeySlot", "ram", 0x0009ba),
		new Entry("MG_CardKeyIndex", "ram", 0x0009bc),
		new Entry("MG_Key_Status_Array", "ram", 0x0009be),
		new Entry("Mecha_State", "ram", 0x0009ce),
		new Entry("Mecha_Result", "ram", 0x0009d0),
		new Entry("MG_LastBitTable", "ram", 0x0009d2),
		new Entry("MG_Data_Size", "ram", 0x0009d4),
		new Entry("MG_Buffer_Offset", "ram", 0x0009d6),
		new Entry("MG_Data_Out_Offset", "ram", 0x0009d8),
		new Entry("MG_CurrentBlockIdx", "ram", 0x0009de),
		new Entry("MG_Data_Buffer", "ram", 0x0009e2),
		new Entry("MG_Memcard_Nonce", "ram", 0x001572),
		new Entry("MG_Pub_Kc_Part2", "ram", 0x0015ca),
		new Entry("NCMD_Rx_Cmd_ID", "ram", 0x001744),
		new Entry("NCMD_Rx_ParamCnt", "ram", 0x001745),
		new Entry("NCMD_Rx_ParamBuff", "ram", 0x001746),
		new Entry("NCMD_Current_Cmd_ID", "ram", 0x001768),
		new Entry("NCMD_Args", "ram", 0x00176a),
		new Entry("NCMD_Status_Flag", "ram", 0x00177a),
		new Entry("SCMD_Input_Args", "ram", 0x00177c),
		new Entry("RAM_PMAP_Arg_Buffer", "ram", 0x0017b6),
		new Entry("NCMD_Target_LBA", "ram", 0x0017cc),
		new Entry("NCMD_Sector_Count", "ram", 0x0017d4),
		new Entry("Mecha_Hardware_Ready_Flags", "ram", 0x0017ec),
		new Entry("RAM_PS2ID_Buffer", "ram", 0x0017ee),
		new Entry("RAM_EEPROM_Verify_PS2ID", "ram", 0x0017fe),
		new Entry("RAM_ModelName_Config", "ram", 0x00180e),
		new Entry("RAM_DiscDetect_Config", "ram", 0x001820),
		new Entry("RAM_Servo_Config", "ram", 0x001834),
		new Entry("RAM_Tilt_Config", "ram", 0x001898),
		new Entry("RAM_EEGS_Config", "ram", 0x0018a4),
		new Entry("RAM_OSD_Config", "ram", 0x0018e4),
		new Entry("RAM_DVDPlayer_Config", "ram", 0x001954),
		new Entry("Drive_State", "ram", 0x0019c7),
		new Entry("RAM_EEPROM_Task_Flags", "ram", 0x001a10),
		new Entry("RAM_EEPROM_Target_Addr", "ram", 0x001a24),
		new Entry("RAM_Tray_Config", "ram", 0x001a38),
		new Entry("Servo_Mechanics_Enable", "ram", 0x001a68),
		new Entry("RAM_Detect_State_Machine", "ram", 0x001ad6),
		new Entry("RAM_Calibration_Status", "ram", 0x001af6),
		new Entry("RTOS_Msg_Param", "ram", 0x001b08),
		new Entry("Crypto_Msg_Command", "ram", 0x001b0a),
		new Entry("MG_Keys_Buffer", "ram", 0x001b72),
		new Entry("MG_Data_IV_Buffer", "ram", 0x001b92),
		new Entry("Crypto_Engine_State", "ram", 0x001bab),
		new Entry("RAM_Disc_Type", "ram", 0x001d04),
		new Entry("DSP_Tracking_Limit", "ram", 0x00200e),
		new Entry("DSP_Focus_Upper_Limit", "ram", 0x002012),
		new Entry("DSP_Focus_Lower_Limit", "ram", 0x002014),
		new Entry("DSP_Multiplier", "ram", 0x002029),
		new Entry("DSP_Focus_Gain", "ram", 0x0020a8),
		new Entry("UART_Flag_Enable", "ram", 0x0020d8),
		new Entry("RX_Buffer", "ram", 0x0020dc),
		new Entry("TX_Packet_Length", "ram", 0x0020ee),
		new Entry("TX_Error_Flag", "ram", 0x0020ef),
		new Entry("TX_Payload", "ram", 0x0020f0),
		new Entry("IO_Mech_Error_Flags", "io", 0x18),
		new Entry("IO_Spindle_Mode", "io", 0x36),
		new Entry("IO_TIME_MIN", "io", 0xa5),
		new Entry("IO_TIME_SEC", "io", 0xa6),
		new Entry("IO_TIME_FRAME", "io", 0xa7),
	};

	private MechaConSymbols() {
	}
}
