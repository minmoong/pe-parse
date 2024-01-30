#include <iostream>

#include "parser.h"

using namespace std;

void ParseAndPrintHeaders(FILE* fp);

int main(int argc, char* argv[]) {
	system("chcp 65001");

	if (argc != 2) {
		cout << "Usage: " << argv[0] << " [path of PE file]" << endl;
		return -1;
	}

	FILE* fp;
	if (fopen_s(&fp, argv[1], "rb") != 0) {
		cout << "Unable to open file: " << argv[1] << endl;
		return -1;
	}

	ParseAndPrintHeaders(fp);

	return 0;
}

void ParseAndPrintHeaders(FILE* fp) {
	Parser peParser(fp);

	if (peParser.magic == 0x20B) {
		cout << "This program doesn't support PE32+ parse." << endl;
	}

	peParser.ParseDOSHeader();
	peParser.ParseNTHeader();
	peParser.ParseSECTIONHeader();
	peParser.ParseIMPORTDescriptor();

	peParser.PrintDOSHeader();
	peParser.PrintNTHeader32();
	peParser.PrintSECTIONHeader();
	peParser.PrintIMPORTDescriptor();
}