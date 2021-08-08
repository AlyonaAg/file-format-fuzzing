#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <windows.h>
#include <fstream> // работа с файлами
#include <iomanip> // манипуляторы ввода/вывода

const std::string g_config_path("config_4");

void ShowInput() {
	unsigned char* bytes = NULL;
	std::ifstream in(g_config_path, std::ifstream::ate | std::ifstream::binary);
	int bufsize = in.tellg();
	in.seekg(0, std::ios::beg); // возвращаем курсор в начало файла.
	bytes = (unsigned char*)new unsigned char(bufsize + 50);
	memset(bytes, 0, sizeof(bytes));
	int i = 0;
	do {
		bytes[i++] = in.get();
	} while (!in.eof());
	in.close();
	for (int i = 0; i < bufsize; i++) {
		printf("%X ", bytes[i]);
	}
}

int main()
{
	ShowInput();
	return 0;
}