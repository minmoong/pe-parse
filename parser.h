#pragma once

#include "winntdef.h"

#define MAX_SECTIONS 150

using namespace std;

class Parser {
public:
	Parser(FILE* fp);

	BYTE* ReadStringFromRAW(DWORD RAW);
	DWORD RVAtoRAW(DWORD RVA);

	void ParseDOSHeader();
	void ParseNTHeader();
	void ParseSECTIONHeader();
	void ParseIMPORTDescriptor();

	void PrintDOSHeader();
	void PrintNTHeader32();
	void PrintSECTIONHeader();
	void PrintIMPORTDescriptor();

	WORD magic;
	IMAGE_DOS_HEADER DOSHeader = { 0, };
	IMAGE_NT_HEADERS32 NTHeader32 = { 0, };
	IMAGE_SECTION_HEADER* SECTIONHeader = NULL;
	IMAGE_IMPORT_DESCRIPTOR* IMPORTDescriptor = NULL;
private:
	FILE* fp;
};