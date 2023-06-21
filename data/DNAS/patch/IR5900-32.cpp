//
// Find sceDNAS2TitleAuthInfo_t *auth_info parameter in sceDNAS2InitNoHDD function
//
// typedef struct sceDNAS2Data {
// 	void *ptr;
// 	int size;
// } sceDNAS2Data_t;

// typedef struct sceDNAS2TitleAuthInfo {
// 	int line_type;
// 	sceDNAS2Data_t pass_phrase;
// 	sceDNAS2Data_t auth_data;
// } sceDNAS2TitleAuthInfo_t;
//
void scanPassPhraseAndAuthData()
{
	#define sceDNAS2_T_INET 1

	u32 reg_a0 = cpuRegs.GPR.n.a0.UL[0];

	if (reg_a0 <= 0x8000000)
	{
		u32 line_type = memRead32(reg_a0);
		u32 pass_phrase_address = memRead32(reg_a0 + 4);
		u32 pass_phrase_size = memRead32(reg_a0 + 8);
		u32 auth_data_address = memRead32(reg_a0 + 12);
		u32 auth_data_size = memRead32(reg_a0 + 16);

		if (line_type == sceDNAS2_T_INET && pass_phrase_size == 0x8 && auth_data_size == 0x10000)
		{
			u32 reg_pc = cpuRegs.pc;

			Console.WriteLn("--------------------------------------------------");
			Console.WriteLn(fmt::format("pc = {0:x}", reg_pc).c_str());
			Console.WriteLn(fmt::format("line_type = {0:x}", line_type).c_str());
			Console.WriteLn(fmt::format("pass_phrase_address = {0:x}", pass_phrase_address).c_str());
			Console.WriteLn(fmt::format("pass_phrase_size = {0:x}", pass_phrase_size).c_str());
			Console.WriteLn(fmt::format("auth_data_address = {0:x}", auth_data_address).c_str());
			Console.WriteLn(fmt::format("auth_data_size = {0:x}", auth_data_size).c_str());

			FILE* file1;
			FILE* file2;

			file1 = fopen("sstates/pass_phrase", "wb");
			file2 = fopen("sstates/auth_data", "wb");

			for (int j = 0; j < 8; j++)
			{
				unsigned char data = memRead32(pass_phrase_address + j);
				fwrite(&data, sizeof(unsigned char), 1, file1);
			}

			for (int j = 0; j < 0x10000; j++)
			{
				unsigned char data = memRead32(auth_data_address + j);
				fwrite(&data, sizeof(unsigned char), 1, file2);
			}

			fclose(file1);
			fclose(file2);
		}
	}
}

#include <sstream>

void scanPublicKey()
{
	u32 reg_a0 = cpuRegs.GPR.n.a0.UL[0];
	u32 reg_a1 = cpuRegs.GPR.n.a1.UL[0];
	u32 reg_a2 = cpuRegs.GPR.n.a2.UL[0];
	u32 reg_pc = cpuRegs.pc;
	
	// Check CPU registers are addresses
	if (reg_a0 < 0x8000000 && reg_a0 > 0 &&
		reg_a1 < 0x8000000 && reg_a1 > 0 &&
		reg_a2 < 0x8000000 && reg_a2 > 0)
	{
		u32 bigint_a_value_address = memRead32(reg_a0 + 8);
		u32 exponent_address = memRead32(reg_a1 + 8);
		u32 modulo_address = memRead32(reg_a2 + 8);
		
		// Check values are addresses
		if (bigint_a_value_address < 0x8000000 && bigint_a_value_address > 0 &&
			exponent_address < 0x8000000 && exponent_address > 0 &&
			modulo_address   < 0x8000000 && modulo_address   > 0)
		{
			u32 bigint_b_v1 = memRead32(reg_a1);
			u32 bigint_b_v2 = memRead32(reg_a1 + 4);

			u32 bigint_c_v1 = memRead32(reg_a2);
			u32 bigint_c_v2 = memRead32(reg_a2 + 4);

			u32 modulo_begin = memRead32(modulo_address + 124);
			u32 modulo_end = memRead32(modulo_address);

			u32 exponent = memRead32(exponent_address);

			if (bigint_b_v1 >= 1 && bigint_b_v1 <= 32 && bigint_b_v2 >= 1 && bigint_b_v2 <= 32 && 
				bigint_c_v1 >= 1 && bigint_c_v1 <= 32 && bigint_c_v2 >= 1 && bigint_c_v2 <= 32 &&
				modulo_begin != 0xc5c20818 && modulo_end != 0xdbf2cbad &&                          // Bad modulos has a static value
				exponent >= 0x10001 && exponent < 0x10020)                                         // Exponent should be in specific range
			{
				// Debug
				// Console.WriteLn("--------------------------------------------------");
				//Console.WriteLn(fmt::format("pc = 0x{0:x}", reg_pc).c_str());
				//Console.WriteLn(fmt::format("a0 = 0x{0:x}", reg_a0).c_str());
				//Console.WriteLn(fmt::format("a1 = 0x{0:x}", reg_a1).c_str());
				//Console.WriteLn(fmt::format("a2 = 0x{0:x}", reg_a2).c_str());
				//Console.WriteLn(fmt::format("bigint_b_v1 = 0x{0:x}", bigint_b_v1).c_str());
				//Console.WriteLn(fmt::format("bigint_c_v1 = 0x{0:x}", bigint_c_v1).c_str());
				//Console.WriteLn(fmt::format("bigint_b_v2 = 0x{0:x}", bigint_b_v2).c_str());
				//Console.WriteLn(fmt::format("bigint_c_v2 = 0x{0:x}", bigint_c_v2).c_str());
				//Console.WriteLn(fmt::format("exponent_address = 0x{0:x}", exponent_address).c_str());
				//Console.WriteLn(fmt::format("modulo_address = 0x{0:x}", modulo_address).c_str());
				//Console.WriteLn(fmt::format("modulo_begin = {0:x}", modulo_begin).c_str());
				//Console.WriteLn(fmt::format("modulo_end = {0:x}", modulo_end).c_str());
				
				std::stringstream ss;

				// Modulo
				FILE* file1 = fopen("sstates/modulo", "wb");
				for (int j = 127; j >= 0; j--)
				{
					unsigned char data = memRead32(modulo_address + j);
					fwrite(&data, sizeof(unsigned char), 1, file1);

					ss << std::hex << std::setfill('0') << std::setw(2) << (int)(data);
				}
				fclose(file1);
				
				// Exponent
				FILE* file2 = fopen("sstates/exponent", "wb");
				for (int j = 3; j >= 0; j--)
				{
					unsigned char data = (exponent >> (j * 8)) & 0xFF;
					fwrite(&data, sizeof(unsigned char), 1, file1);
				}
				fclose(file2);

				// Modulo and Exponent
				Console.WriteLn(fmt::format("modulo = 0x{0:s}", ss.str()).c_str());
				Console.WriteLn(fmt::format("exponent = 0x{0:x} ({0})", exponent).c_str());
			}
		}
	}
}

void recompileNextInstruction(bool delayslot, bool swapped_delay_slot)
{
	scanPassPhraseAndAuthData();
	scanPublicKey();