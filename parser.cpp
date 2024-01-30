#include <iostream>
#include <iomanip>
#include <string>

#include "parser.h"

#define PRINT_FIELD_WIDTH 20
#define PRINT_HEX_WIDTH 8

void PrintColumnName() {
	cout << left << setw(PRINT_FIELD_WIDTH) << "Field" << " " << right << setw(PRINT_HEX_WIDTH) << "Value" << "  " << "Description" << endl;
}

void PrintLine(string field, size_t value, string description) {
	cout << uppercase << hex;
	cout << left << setw(PRINT_FIELD_WIDTH) << field << " " << right << setw(PRINT_HEX_WIDTH) << setfill(' ') << value << "  " << description << endl;
}

Parser::Parser(FILE* filePtr) {
	fp = filePtr;

	// Parse architecture
	LONG e_lfanew;
	fseek(fp, offsetof(IMAGE_DOS_HEADER, e_lfanew), SEEK_SET);
	fread(&e_lfanew, sizeof(LONG), 1, fp);

	fseek(fp, e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader), SEEK_SET);
	fread(&magic, sizeof(WORD), 1, fp);
}

BYTE* Parser::ReadStringFromRAW(DWORD RAW) {
	BYTE* str = (BYTE*)malloc(sizeof(BYTE) * 256);
	DWORD i = 0;

	fseek(fp, RAW, SEEK_SET);
	do {
		fread(&str[i], 1, 1, fp);
		i++;
	} while (str[i - 1] != 0);

	return str;
}

DWORD Parser::RVAtoRAW(DWORD RVA) {
	DWORD RAW = 64;

	for (int i = 0; i < NTHeader32.FileHeader.NumberOfSections; ++i) {
		if (RVA >= SECTIONHeader[i].VirtualAddress && RVA < SECTIONHeader[i + 1].VirtualAddress) {
			RAW = RVA - SECTIONHeader[i].VirtualAddress + SECTIONHeader[i].PointerToRawData;
		}
	}

	return RAW;
}

void Parser::ParseDOSHeader() {
	fseek(fp, 0, SEEK_SET);
	fread(&DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, fp);
}

void Parser::ParseNTHeader() {
	fseek(fp, DOSHeader.e_lfanew, SEEK_SET);
	fread(&NTHeader32, sizeof(IMAGE_NT_HEADERS32), 1, fp);
}

void Parser::ParseSECTIONHeader() {
	SECTIONHeader = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * NTHeader32.FileHeader.NumberOfSections);

	DWORD offset = DOSHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);

	for (int i = 0; i < NTHeader32.FileHeader.NumberOfSections; ++i) {
		fseek(fp, offset + sizeof(IMAGE_SECTION_HEADER) * i, SEEK_SET);
		fread(&(SECTIONHeader[i]), sizeof(IMAGE_SECTION_HEADER), 1, fp);
	}
}

void Parser::ParseIMPORTDescriptor() {
	IMPORTDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)malloc(NTHeader32.OptionalHeader.DataDirectory[1].Size);

	DWORD offset = RVAtoRAW(NTHeader32.OptionalHeader.DataDirectory[1].VirtualAddress);
	DWORD numberOfDescriptor = NTHeader32.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	for (int i = 0; i < numberOfDescriptor - 1; ++i) {
		fseek(fp, offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) * i, SEEK_SET);
		fread(&(IMPORTDescriptor[i]), sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, fp);
	}
}

void Parser::PrintDOSHeader() {
	cout << "\033[1;34m" << "[IMAGE_DOS_HEADER]" << "\033[0m" << endl;
	PrintColumnName();
	PrintLine("e_magic", DOSHeader.e_magic, "DOS signature (\"MZ\")");
	PrintLine("e_lfanew", DOSHeader.e_lfanew, "Offset to NT header");
	cout << endl;
}

void Parser::PrintNTHeader32() {
	cout << "\033[1;34m" << "[IMAGE_NT_HEADERS32]" << "\033[0m" << endl;
	PrintColumnName();
	PrintLine("Signature", NTHeader32.Signature, "PE signature (\"PE\")");
	cout << endl;

	cout << "\033[1;34m" << "[IMAGE_NT_HEADERS32 - IMAGE_FILE_HEADER]" << "\033[0m" << endl;
	PrintColumnName();
	PrintLine("Machine", NTHeader32.FileHeader.Machine, "Machine");
	PrintLine("NumberOfSections", NTHeader32.FileHeader.NumberOfSections, "Number of sections");
	PrintLine("SizeOfOptionalHeader", NTHeader32.FileHeader.SizeOfOptionalHeader, "Size of optional header");
	PrintLine("Characteristics", NTHeader32.FileHeader.Characteristics, "File characteristics");
	cout << endl;


	cout << "\033[1;34m" << "[IMAGE_NT_HEADERS32 - IMAGE_OPTIONAL_HEADER32]" << "\033[0m" << endl;
	PrintColumnName();
	PrintLine("Magic", NTHeader32.OptionalHeader.Magic, NTHeader32.OptionalHeader.Magic == 0x10B ? "0x10B - Use IMAGE_OPTIONAL_HEADER32" : "0x20B - Use IMAGE_OPTIONAL_HEADER64");
	PrintLine("AddressOfEntryPoint", NTHeader32.OptionalHeader.AddressOfEntryPoint, "RVA of entry point");
	PrintLine("ImageBase", NTHeader32.OptionalHeader.ImageBase, "Image base");
	PrintLine("SectionAlignment", NTHeader32.OptionalHeader.SectionAlignment, "Minimum unit of section in memory");
	PrintLine("FileAlignment", NTHeader32.OptionalHeader.FileAlignment, "Minimum unit of section in file");
	PrintLine("SizeOfImage", NTHeader32.OptionalHeader.SizeOfImage, "Size of PE image (when loaded to memory)");
	PrintLine("SizeOfHeaders", NTHeader32.OptionalHeader.SizeOfHeaders, "Size of PE header");
	PrintLine("Subsystem", NTHeader32.OptionalHeader.Subsystem, "Subsystem");
	PrintLine("NumberOfRvaAndSizes", NTHeader32.OptionalHeader.NumberOfRvaAndSizes, "Number of directories");

	string DirectoryNames[] = { "EXPORT", "IMPORT", "RESOURCE",
								"EXCEPTION", "SECURITY", "BASERELOC",
								"DEBUG", "COPYRIGHT", "GLOBALPTR",
								"TLS", "LOAD_CONFIG", "BOUND_IMPORT",
								"IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "Reserved" };
	for (int i = 0; i < NTHeader32.OptionalHeader.NumberOfRvaAndSizes; i++) {
		string field = "DataDirectory[" + to_string(i) + "]";
		string description = DirectoryNames[i] + " Directory";
		PrintLine(field, NTHeader32.OptionalHeader.DataDirectory[i].VirtualAddress, "RVA  of " + description);
		PrintLine(field, NTHeader32.OptionalHeader.DataDirectory[i].Size, "Size of " + description);
	}
	cout << endl;
}

void Parser::PrintSECTIONHeader() {
	cout << "\033[1;34m" << "[IMAGE_SECTION_HEADER]" << "\033[0m" << endl;
	PrintColumnName();
	for (int i = 0; i < NTHeader32.FileHeader.NumberOfSections; ++i) {
		cout << left << setw(PRINT_FIELD_WIDTH) << "Name" << " " << right << setw(PRINT_HEX_WIDTH) << setfill(' ') << SECTIONHeader[i].Name << "  " << "Name of section" << endl;
		PrintLine("VirtualSize", SECTIONHeader[i].Misc.VirtualSize, "Size of section (in memory)");
		PrintLine("VirtualAddress", SECTIONHeader[i].VirtualAddress, "RVA of section (in memory)");
		PrintLine("SizeOfRawData", SECTIONHeader[i].SizeOfRawData, "Size of section (in file)");
		PrintLine("PointerToRawData", SECTIONHeader[i].PointerToRawData, "Offset of section (in file)");
		PrintLine("Characteristics", SECTIONHeader[i].Characteristics, "Characteristics of section");
		cout << endl;
	}
}

void Parser::PrintIMPORTDescriptor() {
	DWORD numberOfDescriptor = NTHeader32.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	cout << "\033[1;34m" << "[IMAGE_IMPORT_DESCRIPTOR]" << "\033[0m" << endl;
	for (int i = 0; i < numberOfDescriptor - 1; ++i) {
		cout << left << uppercase << hex;
		cout << "Name: " << ReadStringFromRAW(RVAtoRAW(IMPORTDescriptor[i].Name)) << endl;
		cout << "RVA of IAT: " << IMPORTDescriptor[i].FirstThunk << " (RAW: " << RVAtoRAW(IMPORTDescriptor[i].FirstThunk) << ")" << endl;
		cout << "Import Name Table" << endl;

		DWORD thunk;
		DWORD j = 0;
		DWORD raw = RVAtoRAW(IMPORTDescriptor[i].DUMMYUNIONNAME.OriginalFirstThunk);
		while (true) {
			fseek(fp, raw + sizeof(DWORD) * j, SEEK_SET);
			fread(&thunk, sizeof(DWORD), 1, fp);

			if (!thunk) break;

			cout << "\t" << ReadStringFromRAW(RVAtoRAW(thunk) + sizeof(WORD)) << endl;

			j++;
		}

		cout << endl;
	}
}
