#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string> 
#include <windows.h>
#include <vector>

const size_t header = 54;

std::string config_name = "config_1";
std::string config_default_name = "config_d_1";
std::string vuln_name = "vuln1.exe";
std::string log_name = "log.txt";
std::string change_name = "change.txt";

std::vector <size_t> indexes;

size_t size_config = 0;

void WriteRegisters(CONTEXT* cont, std::string error, HANDLE hProcess)
{
	unsigned char buffer[4048] = { 0 };
	SIZE_T recvSize = 0;

	std::ofstream log_file(log_name, std::ios::app);
	if (!log_file.is_open())
	{
		std::cerr << "Error open log file (GetRegistersState() function)." << std::endl;
		return;
	}

	log_file << "Exception: " << error.c_str() << std::endl;
	log_file << "\tEAX\t:\t0x" << (void*)cont->Eax << "\tESP\t:\t0x" << (void*)cont->Esp << std::endl;
	log_file << "\tEBX\t:\t0x" << (void*)cont->Ebx << "\tEBP\t:\t0x" << (void*)cont->Ebp << std::endl;
	log_file << "\tECX\t:\t0x" << (void*)cont->Ecx << "\tEDI\t:\t0x" << (void*)cont->Edi << std::endl;
	log_file << "\tEDX\t:\t0x" << (void*)cont->Edx << "\tESI\t:\t0x" << (void*)cont->Esi << std::endl;
	log_file << "\tEIP\t:\t0x" << (void*)cont->Eip << "\tFLG\t:\t0x" << (void*)cont->EFlags << std::endl;

	ReadProcessMemory(hProcess, (void*)cont->Esp, buffer, sizeof(buffer), &recvSize);

	if (recvSize != 0)
	{
		std::cout << "stek: " << recvSize << " byte read" << std::endl;
		log_file << std::endl << "Stek (" << recvSize/2 << " byte read):" << std::endl;

		for (int i = 0; i < recvSize/2; i++)
		{
			if (i % 4 == 0)
				log_file << std::endl << "0x" << (void*)((char*)cont->Esp + i) << " :\t";

			log_file.fill('0');
			log_file << std::setw(2) << std::hex << std::uppercase << (int)buffer[i] << " ";
		}
	}
	else
		std::cout << "ReadProcessMemory fail: " << GetLastError() << std::endl;

	log_file << std::endl << "----------------------------------------" << std::endl;

	std::ofstream change_file(change_name, std::ios::app);
	change_file << "\t\tException: " << error.c_str() << std::endl;
	change_file.close();

	log_file.close();
}

bool CharacterComparison(unsigned char s1, unsigned char s2, unsigned char s3, unsigned char s4, unsigned char s5, 
	unsigned char s6, unsigned char s7, unsigned char s8, unsigned char s9, unsigned char s10)
{
	size_t summ = s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8 + s9 + s10;

	if (summ % 10 != 0)
		return false;

	if (summ / 10 != s1 || summ / 10 != s2 || summ / 10 != s3 || summ / 10 != s4 || summ / 10 != s5)
		return false;

	return true;
}

void CountSizeConfig()
{
	size_config = 0;
	std::ifstream conf_file(config_name, std::ios::binary);
	if (!conf_file.is_open())
	{
		std::cerr << "Error open config file (CountSizeConfig() function)." << std::endl;
		return;
	}

	conf_file.seekg(0, std::ios::end);
	size_config = conf_file.tellg();

	conf_file.close();
}

void ShowHex()
{
	std::ifstream conf_file(config_name, std::ios::binary);
	if (!conf_file.is_open())
	{
		std::cerr << "Error open config file (ShowHex() function)." << std::endl;
		return;
	}

	unsigned char symbol;
	size_t count_v = 0, count_g = 0;

	std::cout.fill('0');
	std::cout << "Offset  ";
	for (size_t i = 0; i <= 0x0F; i++)
		std::cout << std::setw(2) << std::hex << std::uppercase << i << " ";
	std::cout << std::endl << std::endl;

	std::cout << std::setw(6) << std::hex << std::uppercase << count_g << "  ";
	do
	{
		symbol = conf_file.get();
		if (conf_file.eof())
			break;

		std::cout << std::setw(2) << std::hex << std::uppercase << static_cast<int>(symbol) << " ";
		count_v++;
		if (count_v > 0x0F)
		{
			count_v = 0, count_g+= 0x10;
			std::cout << std::endl;
			std::cout << std::setw(6) << std::hex << std::uppercase << count_g << "  ";
		}
	} while (!conf_file.eof());

	conf_file.close();
	std::cout << std::endl << std::endl;
}


void ChangeByte(size_t offset, unsigned char byte)
{
	std::fstream conf_file(config_name);
	if (!conf_file.is_open())
	{
		std::cerr << "Error open config file (ChangeByte() function)." << std::endl;
		return;
	}

	conf_file.seekp(offset, std::ios::beg);
	conf_file << byte;

	conf_file.close();
}

void ChangeLengthField(size_t size)
{
	unsigned char new_size_byte1 = size, new_size_byte2 = size >> 8;

	ChangeByte(0x04, new_size_byte1);
	ChangeByte(0x05, new_size_byte2);
	ChangeByte(0x10, new_size_byte1);
	ChangeByte(0x11, new_size_byte2);

	std::ofstream change_file(change_name, std::ios::app);
	change_file << std::dec << "> file length in header field replaced to " << size << std::endl;
	change_file.close();
}

void ChangeSizeBufferField(size_t size)
{
	unsigned char new_size_byte1 = size, new_size_byte2 = size >> 8;

	std::ofstream change_file(change_name, std::ios::app);
	change_file << std::dec << "> the size of the buffer in the header field is changed to " << size << std::endl;
	ChangeByte(0x08, new_size_byte1);
	ChangeByte(0x09, new_size_byte2);
	ChangeByte(0x12, new_size_byte1);
	ChangeByte(0x13, new_size_byte2);
	change_file.close();
}

void WriteFile(unsigned char byte, size_t count)
{
	CountSizeConfig();
	std::ofstream conf_file(config_name, std::ios::binary | std::ios::app);
	if (!conf_file.is_open())
	{
		std::cerr << "Error open config file (WriteFile() function)." << std::endl;
		return;
	}

	//занесение изменение в файл измнений
	std::ofstream change_file(change_name, std::ios::app);
	change_file << std::dec << "> " << count << " bytes (0x" << std::hex << (int)byte << ") added to the end of the file" << std::endl;

	ChangeByte(size_config - 1, byte);
	for (size_t i = 0; i < count-1; conf_file<<byte, i++);
	byte = 0;
	conf_file << byte;
	size_config += count;
	
	change_file.close();
	conf_file.close();
}


void ResetConfig()
{
	BOOL res = CopyFileA(config_default_name.c_str(), config_name.c_str(), false);
	if (res == false)
		std::cerr << "CopyFileA fail: " << GetLastError() << std::endl;

	std::ofstream change_file(change_name, std::ios::app);
	change_file << "-------------------------------------------------" << std::endl;
	change_file.close();
}

void RunProgram()
{
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	DEBUG_EVENT debug_event = { 0 };
	HANDLE thread;
	CONTEXT cont;

	BOOL status;

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	status = CreateProcessA(vuln_name.c_str(), NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);
	if (status == false)
	{
		std::cerr << std::dec << "CreateProcess fail: " << GetLastError() << std::endl;
		return;
	}

	while (true)
	{
		status = WaitForDebugEvent(&debug_event, 500);
		if (status == false)
		{
			if (GetLastError() != ERROR_SEM_TIMEOUT)
				std::cerr << "WaitForDebugEvent fail: " << std::dec << GetLastError() << std::endl;
			break;
		}

		if (debug_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
		{
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
			continue;
		}

		thread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
		if (thread == NULL)
		{
			std::cerr << "OpenThread failed: " << std::dec << GetLastError() << std::endl;
			break;
		}

		cont.ContextFlags = CONTEXT_FULL;

		status = GetThreadContext(thread, &cont);
		if (status == false)
		{
			std::cerr << "GetThreadContext failed: " << std::dec << GetLastError() << std::endl;
			CloseHandle(thread);
			break;
		}

		switch (debug_event.u.Exception.ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_ACCESS_VIOLATION:
			WriteRegisters(&cont, "EXCEPTION_ACCESS_VIOLATION", pi.hProcess);
			break;
		case EXCEPTION_STACK_OVERFLOW:
			WriteRegisters(&cont, "EXCEPTION_STACK_OVERFLOW", pi.hProcess);
			break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			WriteRegisters(&cont, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED", pi.hProcess);
			break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			WriteRegisters(&cont, "EXCEPTION_DATATYPE_MISALIGNMENT", pi.hProcess);
			break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			WriteRegisters(&cont, "EXCEPTION_FLT_DENORMAL_OPERAND", pi.hProcess);
			break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			WriteRegisters(&cont, "EXCEPTION_FLT_DIVIDE_BY_ZERO", pi.hProcess);
			break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			WriteRegisters(&cont, "EXCEPTION_FLT_INEXACT_RESULT", pi.hProcess);
			break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			WriteRegisters(&cont, "EXCEPTION_FLT_INVALID_OPERATION", pi.hProcess);
			break;
		case EXCEPTION_FLT_OVERFLOW:
			WriteRegisters(&cont, "EXCEPTION_FLT_OVERFLOW", pi.hProcess);
			break;
		case EXCEPTION_FLT_STACK_CHECK:
			WriteRegisters(&cont, "EXCEPTION_FLT_STACK_CHECK", pi.hProcess);
			break;
		case EXCEPTION_FLT_UNDERFLOW:
			WriteRegisters(&cont, "EXCEPTION_FLT_UNDERFLOW", pi.hProcess);
			break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			WriteRegisters(&cont, "EXCEPTION_ILLEGAL_INSTRUCTION", pi.hProcess);
			break;
		case EXCEPTION_IN_PAGE_ERROR:
			WriteRegisters(&cont, "EXCEPTION_IN_PAGE_ERROR", pi.hProcess);
			break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			WriteRegisters(&cont, "EXCEPTION_INT_DIVIDE_BY_ZERO", pi.hProcess);
		case EXCEPTION_INT_OVERFLOW:
			WriteRegisters(&cont, "EXCEPTION_INT_OVERFLOW", pi.hProcess);
			break;
		case EXCEPTION_INVALID_DISPOSITION:
			WriteRegisters(&cont, "EXCEPTION_INVALID_DISPOSITION", pi.hProcess);
			break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			WriteRegisters(&cont, "EXCEPTION_NONCONTINUABLE_EXCEPTION", pi.hProcess);
			break;
		case EXCEPTION_PRIV_INSTRUCTION:
			WriteRegisters(&cont, "EXCEPTION_PRIV_INSTRUCTION", pi.hProcess);
			break;
		case EXCEPTION_SINGLE_STEP:
			WriteRegisters(&cont, "EXCEPTION_SINGLE_STEP", pi.hProcess);
			break;
		default:
			std::cout << "Unknown exception: " << std::dec << debug_event.u.Exception.ExceptionRecord.ExceptionCode << std::endl;
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
		}
		CloseHandle(thread);
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void AutoChange()
{
	CountSizeConfig();
	std::string command;
	size_t value[] = {
		0x00,
		0xFF,
		0xFF / 2 - 1,
		0xFF / 2 + 1,
		0x0000,
		0xFFFF,
		0xFFFF / 2 - 1,
		0xFFFF / 2 + 1,
		0x000000,
		0xFFFFFF,
		0xFFFFFF / 2 - 1,
		0xFFFFFF / 2 + 1,
		0x00000000,
		0xFFFFFFFF,
		0xFFFFFFFF / 2 - 1,
		0xFFFFFFFF / 2 + 1,
	};

	std::cout << "Select an option:" << std::endl;
	std::cout << "\t1 - one-byte replacement" << std::endl;
	std::cout << "\t2 - two-byte replacement" << std::endl;
	std::cout << "\t3 - three-byte replacement" << std::endl;
	std::cout << "\t4 - four-byte replacement" << std::endl;

	std::getline(std::cin, command);

	std::ofstream change_file(change_name, std::ios::app);

	if (command == "1")
	{
		for (size_t i = 0; i < 4; i++, Sleep(20000))
			for (size_t j = 0; j < header; j++)
			{
				ChangeByte(j, value[i]);
				change_file << std::hex << "> byte in place 0x" << j << " replaced by \"0x" << (int)value[i] << "\"" << std::endl;
				RunProgram();
				ResetConfig();
			}
	}
	else if (command == "2")
	{
		for (size_t i = 4; i < 8; i++, Sleep(20000))
			for (size_t j = 0; j < header; j++)
			{
				ChangeByte(j, value[i]>>8);
				ChangeByte(j + 1, value[i]);
				change_file << std::hex << "> bytes from 0x" << j << " to 0x" << j + 1 << " replaced by \"0x" << (int)value[i] << "\"" << std::endl;
				RunProgram();
				ResetConfig();
			}
	}
	else if (command == "3")
	{
		for (size_t i = 9; i < 12; i++, Sleep(20000))
			for (size_t j = 0; j < header; j ++)
			{
				ChangeByte(j, value[i] >> 16);
				ChangeByte(j + 1, value[i] >> 8);
				ChangeByte(j + 2, value[i]);
				change_file << std::hex << "> bytes from 0x" << j << " to 0x" << j + 2 << " replaced by \"0x" << (int)value[i] << "\"" << std::endl;
				RunProgram();
				ResetConfig();
			}
	}
	else if (command == "4")
	{
		for (size_t i = 12; i < 16; i++, Sleep(20000))
			for (size_t j = 0; j < header; j ++)
			{
				ChangeByte(j, value[i] >> 24);
				ChangeByte(j + 1, value[i] >> 16);
				ChangeByte(j + 2, value[i] >> 8);
				ChangeByte(j + 3, value[i]);
				change_file << std::hex << "> bytes from 0x" << j << " to 0x" << j+3 << " replaced by \"0x" << (int)value[i] << "\"" << std::endl;
				RunProgram();
				ResetConfig();
			}
	}
	change_file.close();
}

void FindSymbol(unsigned char desired_symbol)
{
	std::ifstream conf_file(config_name);
	if (!conf_file.is_open())
	{
		std::cerr << "Error open config file (FindSymbol() function)." << std::endl;
		return;
	}

	char symbol;
	size_t index = 0;
	bool flag = false;
	do
	{
		symbol = conf_file.get();
		if (conf_file.eof())
			break;
		if (symbol == desired_symbol)
		{
			std::cout << "Symbol " << desired_symbol << " found by index " << index << std::endl;
			flag = true;
		}
		index++;
	} while (!conf_file.eof());
	
	if(!flag)
		std::cout << "Symbol " << desired_symbol << " not found" << std::endl;

	conf_file.close();
}

void SearchForBoundaries()
{
	size_t index = 0;

	std::ifstream conf_file1("config_1", std::ios::binary);
	std::ifstream conf_file2("config_2", std::ios::binary);
	std::ifstream conf_file3("config_3", std::ios::binary);
	std::ifstream conf_file4("config_4", std::ios::binary);
	std::ifstream conf_file5("config_5", std::ios::binary);
	std::ifstream conf_file11("config_11", std::ios::binary);
	std::ifstream conf_file21("config_21", std::ios::binary);
	std::ifstream conf_file31("config_31", std::ios::binary);
	std::ifstream conf_file41("config_41", std::ios::binary);
	std::ifstream conf_file51("config_51", std::ios::binary);

	unsigned char symbol1, symbol2,symbol11;
	do
	{
		while (CharacterComparison(conf_file1.get(), conf_file2.get(), conf_file3.get(), conf_file4.get(), conf_file5.get(),
			conf_file11.get(), conf_file21.get(), conf_file31.get(), conf_file41.get(), conf_file51.get()));
		while (!CharacterComparison(conf_file1.get(), conf_file2.get(), conf_file3.get(), conf_file4.get(), conf_file5.get(),
			conf_file11.get(), conf_file21.get(), conf_file31.get(), conf_file41.get(), conf_file51.get()));

		index = conf_file1.tellg();
		indexes.push_back(index - 2);
	} while (index < header);


	conf_file1.close();
	conf_file2.close();
	conf_file3.close();
	conf_file4.close();
	conf_file5.close();
	conf_file11.close();
	conf_file21.close();
	conf_file31.close();
	conf_file41.close();
	conf_file51.close();
}

void PrintBoundaries()
{
	SearchForBoundaries();

	std::ifstream conf_file(config_name, std::ios::binary);
	if (!conf_file.is_open())
	{
		std::cerr << "Error open config file (PrintBoundaries() function)." << std::endl;
		return;
	}

	unsigned char symbol;
	size_t index_config = 0, index = 0;
	std::cout << "Header: " << std::endl;
	do
	{
		symbol = conf_file.get();
		if (conf_file.eof())
			break;

		std::cout.fill('0');
		std::cout << std::setw(2) << std::hex << std::uppercase << static_cast<int>(symbol) << " ";
		if (index<indexes.size() && index_config == indexes[index])
		{
			index++;
			std::cout << " |  ";
		}
		index_config++;
	} while (!conf_file.eof() && index_config < header);


	std::cout << std::endl;

	conf_file.close();
}

bool CompareFiles()
{
	std::ifstream conf_file(config_name, std::ios::binary);
	std::ifstream conf_default_file(config_default_name, std::ios::binary);

	if (!conf_file.is_open() || !conf_default_file.is_open())
	{
		std::cerr << "Error open config file (CompareFiles() function)." << std::endl;
		return false;
	}

	unsigned char symbol1, symbol2;

	do
	{
		symbol1 = conf_file.get();
		symbol2 = conf_default_file.get();

		if (symbol1 != symbol2)
		{
			conf_file.close();
			conf_default_file.close();
			return false;
		}

		if (conf_file.eof() || conf_default_file.eof())
			break;
	} while (!conf_file.eof() && !conf_default_file.eof());

	if (conf_file.eof() && !conf_default_file.eof() ||
		!conf_file.eof() && conf_default_file.eof())
	{
		conf_file.close();
		conf_default_file.close();
		return false;
	}

	conf_file.close();
	conf_default_file.close();
	return true;
}

void Menu()
{
	std::string command;
	size_t offset, byte, count;

	while (1) {

		std::cout << "Select an option:" << std::endl;
		std::cout << "\t1 - show config" << std::endl;
		std::cout << "\t2 - one-byte replacement" << std::endl;
		std::cout << "\t3 - replacing multiple bytes" << std::endl;
		std::cout << "\t4 - append to the end of the file" << std::endl;
		std::cout << "\t5 - automatic byte replacement" << std::endl;
		std::cout << "\t6 - run vuln.exe" << std::endl;		
		std::cout << "\t7 - find characters separating fields (=,:;)" << std::endl;
		std::cout << "\t8 - finding field boundaries" << std::endl;
		std::cout << "\t9 - increase line length in file (change field)" << std::endl;
		std::cout << "\t10 - increase size buffer in file (change field)" << std::endl;
		std::cout << "\t11 - exit" << std::endl;

		if (!std::getline(std::cin, command))
			break;

		if (command == "1")
			ShowHex();
		else if (command == "2")
		{
			std::cout << "Enter offset: ";
			std::cin >> std::hex >> offset;
			std::cout << "Enter byte: ";
			std::cin >> std::hex >> byte;
			std::cin.ignore(256, '\n');
			ChangeByte(offset, byte);
			std::ofstream change_file(change_name, std::ios::app);
			change_file << std::hex << "> byte in place 0x" << offset << " replaced by \"0x" << (int)byte << "\"" << std::endl;
			change_file.close();
		}
		else if (command == "3")
		{
			std::cout << "Enter start offset: ";
			std::cin >> std::hex >> offset;
			std::cout << "Enter byte: ";
			std::cin >> std::hex >> byte;
			std::cout << "Enter count: ";
			std::cin >> std::dec >> count;
			std::cin.ignore(256, '\n');
			for (size_t i = offset; i < offset + count; ChangeByte(i, byte), i++);
			std::ofstream change_file(change_name, std::ios::app);
			change_file << std::hex << "> bytes from 0x" << offset << " to 0x" << offset + count << " replaced by \"0x" << (int)byte << "\"" << std::endl;
			change_file.close();
		}
		else if (command == "4")
		{
			std::cout << "Enter byte: ";
			std::cin >> std::hex >> byte;
			std::cout << "Enter count: ";
			std::cin >> std::dec >> count;
			std::cin.ignore(256, '\n');
			WriteFile(byte, count);
		}
		else if (command == "5")
			AutoChange();
		else if (command == "6")
			RunProgram();
		else if (command == "7")
		{
			FindSymbol('=');
			FindSymbol(':');
			FindSymbol(';');
			FindSymbol('.');
		}
		else if (command == "8")
			PrintBoundaries();
		else if (command == "9")
		{
			std::cout << "Enter new lenght: ";
			std::cin >> std::dec >> count;
			std::cin.ignore(256, '\n');
			ChangeLengthField(count);
		}
		else if (command == "10")
		{
			std::cout << "Enter new max buffer size: ";
			std::cin >> std::dec >> count;
			std::cin.ignore(256, '\n');
			ChangeSizeBufferField(count);
		}
		else if (command == "11")
			break;
		else if (command == "12")
			ResetConfig();
	}
}

int main()
{
	if (CompareFiles())
	{
		std::ofstream change_file(change_name, std::ios::app);
		change_file << "-------------------------------------------------" << std::endl;
		change_file.close();
	}
	Menu();	
	return 0;
}