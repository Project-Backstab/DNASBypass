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

void scanPublicKey()
{
	u32 reg_a0 = cpuRegs.GPR.n.a0.UL[0];
	u32 reg_a1 = cpuRegs.GPR.n.a1.UL[0];
	u32 reg_a2 = cpuRegs.GPR.n.a2.UL[0];
	u32 reg_pc = cpuRegs.pc;
	
	if (reg_a0 < 0x8000000 && reg_a1 < 0x8000000 && reg_a2 < 0x8000000)
	{
		u32 bigint_a_v1 = memRead32(reg_a0);
		u32 bigint_a_v2 = memRead32(reg_a0 + 4);
		u32 bigint_a_value_address = memRead32(reg_a0 + 8);

		u32 bigint_b_v1 = memRead32(reg_a1);
		u32 bigint_b_v2 = memRead32(reg_a1 + 4);
		u32 bigint_b_value_address = memRead32(reg_a1 + 8);

		u32 bigint_c_v1 = memRead32(reg_a2);
		u32 bigint_c_v2 = memRead32(reg_a2 + 4);
		u32 bigint_c_value_address = memRead32(reg_a2 + 8);
		
		if (bigint_a_v1 >= 1 && bigint_a_v1 <= 32 && bigint_a_v2 >= 1 && bigint_a_v2 <= 32 && bigint_a_value_address < 0x8000000 && bigint_a_value_address > 0x0 &&
			bigint_b_v1 >= 1 && bigint_b_v1 <= 32 && bigint_b_v2 >= 1 && bigint_b_v2 <= 32 && bigint_b_value_address < 0x8000000 && bigint_b_value_address > 0x0 &&
			bigint_c_v1 >= 1 && bigint_c_v1 <= 32 && bigint_c_v2 >= 1 && bigint_c_v2 <= 32 && bigint_c_value_address < 0x8000000 && bigint_c_value_address > 0x0)
		{
			Console.WriteLn("--------------------------------------------------");

			Console.WriteLn(fmt::format("pc = {0:x}", reg_pc).c_str());
			Console.WriteLn(fmt::format("a0 = {0:x}", reg_a0).c_str());
			Console.WriteLn(fmt::format("a1 = {0:x}", reg_a1).c_str());
			Console.WriteLn(fmt::format("a2 = {0:x}", reg_a2).c_str());

			Console.WriteLn(fmt::format("bigint_a_v1 = {0:x}", bigint_a_v1).c_str());
			Console.WriteLn(fmt::format("bigint_b_v1 = {0:x}", bigint_b_v1).c_str());
			Console.WriteLn(fmt::format("bigint_c_v1 = {0:x}", bigint_c_v1).c_str());

			Console.WriteLn(fmt::format("bigint_a_v2 = {0:x}", bigint_a_v2).c_str());
			Console.WriteLn(fmt::format("bigint_b_v2 = {0:x}", bigint_b_v2).c_str());
			Console.WriteLn(fmt::format("bigint_c_v2 = {0:x}", bigint_c_v2).c_str());

			Console.WriteLn(fmt::format("bigint_a_value_address = {0:x}", bigint_a_value_address).c_str());
			Console.WriteLn(fmt::format("bigint_b_value_address = {0:x}", bigint_b_value_address).c_str());
			Console.WriteLn(fmt::format("bigint_c_value_address = {0:x}", bigint_c_value_address).c_str());

			FILE* file1;
			
			file1 = fopen("sstates/modulo", "wb");

			for (int j = 0; j < 32; j++)
			{
				u32 data = memRead32(bigint_a_value_address + (j * 4));
				Console.WriteLn(fmt::format("data = {0:x}", data).c_str());
			}

			for (int j = 0; j < 1; j++)
			{
				u32 data = memRead32(bigint_b_value_address + (j * 4));
				Console.WriteLn(fmt::format("data = {0:x}", data).c_str());
			}

			for (int j = 127; j >= 0; j--)
			{
				unsigned char data = memRead32(bigint_c_value_address + j);

				Console.WriteLn(fmt::format("data = {0:x}", data).c_str());

				fwrite(&data, sizeof(unsigned char), 1, file1);
			}

			fclose(file1);
		}
	}
}

void recompileNextInstruction(bool delayslot, bool swapped_delay_slot)
{
	scanPassPhraseAndAuthData();
	scanPublicKey();