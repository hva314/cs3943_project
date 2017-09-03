// CS3943 Group Project
// Anthony Hoang - seu019
// Josh Thorsson - qhb659
// Drake McHugh - hvm851

// Main.cpp

#include <windows.h>
#include <stdio.h>
#include <io.h>

//#define TEST_CODE

// Global Variables
unsigned char gkey[65537];
unsigned char *gptrKey = gkey;			// used for inline assembly routines, need to access this way for Visual Studio
char gPassword[256] = "password";
unsigned char gPasswordHash[32];
unsigned char *gptrPasswordHash = gPasswordHash;	// used for inline assembly routines, need to access this way for Visual Studio

FILE *gfptrIn = NULL;
FILE *gfptrOut = NULL;
FILE *gfptrKey = NULL;
char gInFileName[256];
char gOutFileName[256];
char gKeyFileName[256];
int gOp = 0;			// 1 = encrypt, 2 = decrypt
int gNumRounds = 1;


// Prototypes
int sha256(char *fileName, char *dataBuffer, DWORD dataLength, unsigned char sha256sum[32]);

// assembly language to count the number of ASCII letters in a data array
//	numC = number of capital letters
//	numL = number of lowercase letters
//	numO = number of characters that are not a letter
void exCountLetters(char *data, int dataLength, int *numC, int *numL, int *numO)
{
	__asm {
		cld;					// 
		push esi;				// 
		push ecx;				// 
		push ebx;
		mov esi, data;			// 
		mov ecx, dataLength;	// 

	LOOP_X1:
		lodsb;					// 
		mov bl, al				// 
			push eax;				// 
		call isLetter;			// function returns a 1 in al if the character passed in is a letter, otherwise al = 0
		add esp, 4				// 
			test al, al;				// 
		je lbl_OTHER;			// 

		mov al, bl				// 
			and al, 0x20;			// already know it's a letter, if al == 0, then CAP
		je lbl_CAP;

		mov	ebx, numL;			// 
		add[ebx], 1;			// 
		jmp lbl_NEXT;			// 

	lbl_CAP:
		mov ebx, numC;			// 
		add[ebx], 1;			// 
		jmp lbl_NEXT;			// 

	lbl_OTHER:
		mov ebx, numO			// 
			add[ebx], 1				// 
		lbl_NEXT :
				 dec ecx;				// 
		jne LOOP_X1;			// 

		pop ebx;				// 
		pop ecx;				// 
		pop esi;				// 
		jmp EXIT_C_EXAMPLE;		// let C handle whatever it did upon entering this function

	isLetter:
		push ebp;				// 
		mov ebp, esp;			// 
		mov al, [ebp + 8];			// 
		cmp al, 0x40;			// 
		ja lbl_CHK_ZU;			// check Uppercase 'Z'

	lbl_RET_FALSE:
		xor eax, eax;			// 
	lbl_RET:
		mov esp, ebp;			// 
		pop ebp;				// 
		ret;					// 

	lbl_RET_TRUE:
		mov eax, 1;				// 
		jmp lbl_RET;			// 

	lbl_CHK_ZU:
		cmp al, 0x5B;			// 
		jb lbl_RET_TRUE;		// 

		cmp al, 0x61;			// 
		jb lbl_RET_FALSE;		// check lowercase 'z'

		cmp al, 0x7A;			// 
		jbe lbl_RET_TRUE;		// 
		jmp lbl_RET_FALSE;		// 

	} // end assembly block

EXIT_C_EXAMPLE:					// 
	return;
} // exCountLetters

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to encrypt the data as specified by the project assignment
void encryptData(char *data, int flength)
{
	__asm {

		// local variables
		// [ebp - 0x4] round
		// [ebp - 0x8] starting_point
		// [ebp - 0xc] hop_count
		// [ebp - 0x10] index
		// [ebp - 0x14] x

		// preserve spaces on stack
		sub esp, 0x14;

		xor eax, eax;
		mov[ebp - 0x4], eax; // local variable round

	LOOP_1: // outer loop
		mov ecx, [ebp - 0x4];
		cmp ecx, gNumRounds; // looping condition
		je EXIT_LOOP_1;

		mov esi, gptrPasswordHash; // access gptrPasswordHash

		// Starting_point[round] = gPasswordHash[0+round*4] * 256 + gPasswordHash[1+round*4];
		xor eax, eax;
		mov al, [esi + 0 + ecx * 4];
		shl eax, 8; // multiplied by 256, shifting to left 1 byte
		mov al, [esi + 1 + ecx * 4];
		mov[ebp - 0x8], eax; // starting_point

		// hop_count [round] = gPasswordHash[2+round*4] * 256 + gPasswordHash[3+round*4]; 
		xor eax, eax;
		mov al, [esi + 2 + ecx * 4];
		shl eax, 8; // multiplied by 256, shifting to left 1 byte
		mov al, [esi + 3 + ecx * 4];
		mov[ebp - 0xC], eax; // hop_count

		// if (hop_count == 0) hop_count = 0xFFFF;
		mov eax, [ebp - 0xC];
		cmp eax, 0;
		jne SKIP;
		mov [ebp - 0xC], 0x0000FFFF;
	SKIP:

		// index = starting_point
		mov eax, [ebp - 0x8];
		mov[ebp - 0x10], eax;

		// Loop 2
		xor eax, eax;
		mov[ebp - 0x14], eax;


	LOOP_2:

		// looping condition
		mov ecx, [ebp - 0x14]; // x
		mov eax, flength; 
		cmp ecx, eax; 
		je EXIT_LOOP_2;
		
		// file[x] = file[x] ^ keyfile[index];
		mov edx, [ebp - 0x14]; // x
		mov esi, data;
		mov al, [esi + edx]; // file[x] is in al

		mov edx, [ebp - 0x10]; // index
		mov esi, gptrKey;
		mov bl, [esi + edx]; // keyfile[index] is in bl;

		xor al, bl; // ^ operation
		mov edx, [ebp - 0x14]; // x
		mov edi, data;
		mov[edi + edx], al; // store the value back in file[x]

		// index += hop_count;
		mov eax, [ebp - 0x10];
		add eax, [ebp - 0xc];
		mov[ebp - 0x10], eax;

		// if (index >= 65537) index -= 65537;
		mov eax, [ebp - 0x10];
		cmp eax, 0x10001; // 65537
		jl SKIP2; // skip the next 2 line
		sub eax, 0x10001;
		mov[ebp - 0x10], eax;
	SKIP2:

		///// ----- BEGIN 1-BYTE ENCRYPTION
	
		// store file[x] into al
		xor eax, eax;
		mov edx, [ebp - 0x14]; // x
		mov esi, data;
		mov al, [esi + edx]; // file[x] is in al
		
		// prepare registers
		xor ebx, ebx;
		xor ecx, ecx;
		xor edx, edx;

		// ROTATERIGHT: Moves the bits in the value 1 to the right. Ex. 00110011 becomes 00011001
		ror al, 1;

		// SWAPNIBBLES: Takes the first 4 bits of the value and swaps places with the last 4 bits of the value.  Ex. 11000011 becomes 00111100
		ror al, 4; // simply rotate the byte by 4 bits

		// REVERSEBITS: Reverses the order of bits in the value. ex. 11010011 becomes 11001011
		// move the byte and mask each bit and put them in the correct position
		mov ebx, eax;
		shl ebx, 7;
		and ebx, 0x80;
		or edx, ebx;

		mov ebx, eax;
		shl ebx, 5;
		and ebx, 0x40;
		or  edx, ebx;

		mov ebx, eax;
		shl ebx, 3;
		and ebx, 0x20;
		or  edx, ebx;

		mov ebx, eax;
		shl ebx, 1;
		and ebx, 0x10;
		or  edx, ebx;

		mov ebx, eax;
		shr ebx, 1;
		and ebx, 0x08;
		or  edx, ebx;

		mov ebx, eax;
		shr ebx, 3;
		and ebx, 0x04;
		or  edx, ebx;

		mov ebx, eax;
		shr ebx, 5;
		and ebx, 0x02;
		or  edx, ebx;

		mov ebx, eax;
		shr ebx, 7;
		and ebx, 0x01;
		or edx, ebx;

		and edx, 0x000000FF;
		mov eax, edx;
		
		// SWAPHALFNIBBLES : Takes the first 2 bits of the first 4 bits, and swap it with the last 2 bits of the first 4 bits, for each byte.
		// Ex. 10010011 becomes 01101100

		push eax; // save eax in the stack

		and eax, 0x0000000F; // masking last 4 bits
		mov ebx, eax;

		shr ebx, 2;
		shl eax, 2;

		or eax, ebx;
		and eax, 0x0000000F;
		or ecx, eax;

		pop eax; // reuse the old value

		and eax, 0x000000F0; // masking the first 4 bits
		mov ebx, eax;

		shr ebx, 2;
		shl eax, 2;

		or eax, ebx;
		and eax, 0x000000F0;
		or ecx, eax;
		mov eax, ecx;
		
		// ROTATELEFT: Moves the bits in the value 1 to the left. Ex. 00110011 becomes 01100110
		rol al, 1;

		// write al to file[x]
		mov edx, [ebp - 0x14]; // x
		mov esi, data;
		mov[esi + edx], al;
		
		///// ----- END 1-BYTE ENCRYPTION

		// increment x and loop
		mov ecx, [ebp - 0x14];
		inc ecx;
		mov[ebp - 0x14], ecx; 
		jmp LOOP_2;

	EXIT_LOOP_2:

		// increment round and loop
		mov ecx, [ebp - 0x4];
		inc ecx;
		mov[ebp - 0x4], ecx;
		jmp LOOP_1; 

	EXIT_LOOP_1:

		// restore the stack
		add esp, 0x14; 

	}

//EXIT_C_ENCRYPT_DATA:
	return;
} // encryptData

// code to read the file to encrypt
int encryptFile(FILE *fptrIn, FILE *fptrOut)
{
	char *buffer;
	unsigned int filesize;

	filesize = _filelength(_fileno(fptrIn));	// Linux???
	if (filesize > 0x1000000)					// 16 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *)malloc(filesize);
	if (buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptrIn);	// read entire file
	encryptData(buffer, filesize);
	fwrite(buffer, 1, filesize, fptrOut);
	free(buffer);

	return 0;
} // encryptFile

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to decrypt the data as specified by the project assignment
void decryptData(char *data, int flength)
{
	__asm {

		// local variables
		// [ebp - 0x4] round
		// [ebp - 0x8] starting_point
		// [ebp - 0xc] hop_count
		// [ebp - 0x10] index
		// [ebp - 0x14] x

		// preserve spaces on stack
		sub esp, 0x14;

		// local variable round
		// reverse, round goes from #round - 1 to 0
		mov eax, gNumRounds;
		dec eax;
		mov[ebp - 0x4], eax;

	LOOP_1: // outer loop
		mov ecx, [ebp - 0x4];
		cmp ecx, 0xFFFFFFFF; // looping condition
		je EXIT_LOOP_1;

		mov esi, gptrPasswordHash; // access gptrPasswordHash

		// Starting_point[round] = gPasswordHash[0+round*4] * 256 + gPasswordHash[1+round*4];
		xor eax, eax;
		mov al, [esi + 0 + ecx * 4];
		shl eax, 8; // multiplied by 256, shifting to left 1 byte
		mov al, [esi + 1 + ecx * 4];
		mov[ebp - 0x8], eax; // starting_point

		// hop_count [round] = gPasswordHash[2+round*4] * 256 + gPasswordHash[3+round*4]; 
		xor eax, eax;
		mov al, [esi + 2 + ecx * 4];
		shl eax, 8; // multiplied by 256, shifting to left 1 byte
		mov al, [esi + 3 + ecx * 4];
		mov[ebp - 0xC], eax; // hop_count

		// if (hop_count == 0) hop_count = 0xFFFF;
		mov eax, [ebp - 0xC];
		cmp eax, 0;
		jne SKIP;
		mov[ebp - 0xC], 0x0000FFFF;
	SKIP:

		// index = starting_point
		mov eax, [ebp - 0x8];
		mov[ebp - 0x10], eax;

		// Loop 2
		xor eax, eax;
		mov[ebp - 0x14], eax; // set x to 0

	LOOP_2:

		// looping condition
		mov ecx, [ebp - 0x14]; // x
		mov eax, flength;
		cmp ecx, eax; // compare x to file length
		je EXIT_LOOP_2;

		///// ----- BEGIN 1-BYTE DECRYPTION
		
		// store file[x] into al

		xor eax, eax;
		mov edx, [ebp - 0x14]; // x
		mov esi, data;
		mov al, [esi + edx]; // file[x] is in al

		// ROTATERIGHT: Moves the bits in the value 1 to the right. Ex. 00110011 becomes 00011001
		xor ebx, ebx;
		xor ecx, ecx;
		xor edx, edx;

		ror al, 1;

		// SWAPHALFNIBBLES : Takes the first 2 bits of the first 4 bits, and swap it with the last 2 bits of the first 4 bits, for each byte.
		// Ex. 10010011 becomes 01101100

		push eax; // save eax in the stack

		and eax, 0x0000000F;
		mov ebx, eax;

		shr ebx, 2;
		shl eax, 2;

		or eax, ebx;
		and eax, 0x0000000F;
		or ecx, eax;

		pop eax; // reuse the old value

		and eax, 0x000000F0;
		mov ebx, eax;

		shr ebx, 2;
		shl eax, 2;

		or eax, ebx;
		and eax, 0x000000F0;
		or ecx, eax;
		mov eax, ecx;

		// REVERSEBITS: Reverses the order of bits in the value. ex. 11010011 becomes 11001011
		// mov the byte to different place, mask each bit and put them in correct location
		mov ebx, eax;
		shl ebx, 7;
		and ebx, 0x80;
		or edx, ebx;

		mov ebx, eax;
		shl ebx, 5;
		and ebx, 0x40;
		or  edx, ebx;

		mov ebx, eax;
		shl ebx, 3;
		and ebx, 0x20;
		or  edx, ebx;

		mov ebx, eax;
		shl ebx, 1;
		and ebx, 0x10;
		or  edx, ebx;

		mov ebx, eax;
		shr ebx, 1;
		and ebx, 0x08;
		or  edx, ebx;

		mov ebx, eax;
		shr ebx, 3;
		and ebx, 0x04;
		or  edx, ebx;

		mov ebx, eax;
		shr ebx, 5;
		and ebx, 0x02;
		or  edx, ebx;

		mov ebx, eax;
		shr ebx, 7;
		and ebx, 0x01;
		or edx, ebx;

		and edx, 0x000000FF;
		mov eax, edx;

		// SWAPNIBBLES: Takes the first 4 bits of the value and swaps places with the last 4 bits of the value.  Ex. 11000011 becomes 00111100
		ror al, 4; // simple rotate the byte by 4 bits

		// ROTATELEFT: Moves the bits in the value 1 to the left. Ex. 00110011 becomes 01100110
		rol al, 1;

		// write al to file[x]
		mov edx, [ebp - 0x14]; // x
		mov esi, data;
		mov[esi + edx], al;

		///// ----- END 1-BYTE DECRYPTION

		// file[x] = file[x] ^ keyfile[index];
		mov edx, [ebp - 0x14]; // x
		mov esi, data;
		mov al, [esi + edx]; // file[x] is in al

		mov edx, [ebp - 0x10]; // index
		mov esi, gptrKey;
		mov bl, [esi + edx]; // keyfile[index] is in bl;

		xor al, bl; // ^ operation
		mov edx, [ebp - 0x14]; // x
		mov edi, data;
		mov[edi + edx], al; // store the value back in file[x]

		// index += hop_count;
		mov eax, [ebp - 0x10];
		add eax, [ebp - 0xc];
		mov[ebp - 0x10], eax;

		// if (index >= 65537) index -= 65537;
		mov eax, [ebp - 0x10];
		cmp eax, 0x10001; // 65537
		jl SKIP2;
		sub eax, 0x10001;
		mov[ebp - 0x10], eax;

	SKIP2:

		// increment x and loop
		mov ecx, [ebp - 0x14];
		inc ecx;
		mov[ebp - 0x14], ecx;
		jmp LOOP_2;

	EXIT_LOOP_2:

		// decrement round and loop
		mov ecx, [ebp - 0x4];
		dec ecx;
		mov[ebp - 0x4], ecx;
		jmp LOOP_1;

	EXIT_LOOP_1:
		// restore the stack
		add esp, 0x14;

	}

//EXIT_C_DECRYPT_DATA:
	return;
} // decryptData

// code to read in file and prepare for decryption
int decryptFile(FILE *fptrIn, FILE *fptrOut)
{
	char *buffer;
	unsigned int filesize;

	filesize = _filelength(_fileno(fptrIn));	// Linux???
	if (filesize > 0x1000000)					// 16 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *)malloc(filesize);
	if (buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptrIn);	// read entire file
	decryptData(buffer, filesize);
	fwrite(buffer, 1, filesize, fptrOut);
	free(buffer);

	return 0;
} // decryptFile

//////////////////////////////////////////////////////////////////////////////////////////////////
FILE *openInputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "rb");
	if (fptr == NULL)
	{
		fprintf(stderr, "\n\nError - Could not open input file %s!\n\n", filename);
		exit(-1);
	}
	return fptr;
} // openInputFile

FILE *openOutputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "wb+");
	if (fptr == NULL)
	{
		fprintf(stderr, "\n\nError - Could not open output file %s!\n\n", filename);
		exit(-1);
	}
	return fptr;
} // openOutputFile


void usage(char *argv[])	//   cryptor.exe -e -i <input file> �k <keyfile> -p <password> [�r <#rounds>]
{
	printf("\n\nUsage:\n\n");
	printf("%s -<e=encrypt or d=decrypt> -i <message_filename> -k <keyfile> -p <password> [-r <#rounds>]\n\n", argv[0]);
	printf("-e				:encrypt the specified file\n");
	printf("-d				:decrypt the specified file\n");
	printf("-i filename		:the name of the file to encrypt or decrypt\n");
	printf("-p password		:the password to be used for encryption [default='password']\n");
	printf("-r <#rounds>	:number of encryption rounds (1 - 3)  [default = 1]\n");
	printf("-o filename		:name of the output file [default='encrypted.txt' or 'decrypted.txt'\n\n");
	exit(0);
} // usage

void parseCommandLine(int argc, char *argv[])
{
	int cnt;
	char ch;
	bool i_flag, o_flag, k_flag, p_flag, err_flag;

	i_flag = k_flag = false;				// these must be true in order to exit this function
	err_flag = p_flag = o_flag = false;		// these will generate different actions

	cnt = 1;	// skip program name
	while (cnt < argc)
	{
		ch = *argv[cnt];
		if (ch != '-')
		{
			fprintf(stderr, "All options must be preceeded by a dash '-'\n\n");
			usage(argv);
		}

		ch = *(argv[cnt] + 1);
		if (0)
		{
		}

		else if (ch == 'e' || ch == 'E')
		{
			if (gOp != 0)
			{
				fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
				usage(argv);
			}
			gOp = 1;	// encrypt
		}

		else if (ch == 'd' || ch == 'D')
		{
			if (gOp != 0)
			{
				fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
				usage(argv);
			}
			gOp = 2;	// decrypt
		}

		else if (ch == 'i' || ch == 'I')
		{
			if (i_flag == true)
			{
				fprintf(stderr, "Error! Already specifed an input file.\n\n");
				usage(argv);
			}
			i_flag = true;
			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-i'\n\n");
				usage(argv);
			}
			strncpy(gInFileName, argv[cnt], 256);
		}

		else if (ch == 'o' || ch == 'O')
		{
			if (o_flag == true)
			{
				fprintf(stderr, "Error! Already specifed an output file.\n\n");
				usage(argv);
			}
			o_flag = true;
			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-o'\n\n");
				usage(argv);
			}
			strncpy(gOutFileName, argv[cnt], 256);
		}

		else if (ch == 'k' || ch == 'K')
		{
			if (k_flag == true)
			{
				fprintf(stderr, "Error! Already specifed a key file.\n\n");
				usage(argv);
			}
			k_flag = true;
			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-k'\n\n");
				usage(argv);
			}
			strncpy(gKeyFileName, argv[cnt], 256);
		}

		else if (ch == 'p' || ch == 'P')
		{
			if (p_flag == true)
			{
				fprintf(stderr, "Error! Already specifed a password.\n\n");
				usage(argv);
			}
			p_flag = true;
			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must enter a password after '-p'\n\n");
				usage(argv);
			}
			strncpy(gPassword, argv[cnt], 256);
		}

		else if (ch == 'r' || ch == 'R')
		{
			int x;

			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must enter number between 1 and 3 after '-r'\n\n");
				usage(argv);
			}
			x = atoi(argv[cnt]);
			if (x < 1 || x > 3)
			{
				fprintf(stderr, "Warning! Entered bad value for number of rounds. Setting it to one.\n\n");
				x = 1;
			}
			gNumRounds = x;
		}

		else
		{
			fprintf(stderr, "Error! Illegal option in argument. %s\n\n", argv[cnt]);
			usage(argv);
		}

		cnt++;
	} // end while

	if (gOp == 0)
	{
		fprintf(stderr, "Error! Encrypt or Decrypt must be specified.\n\n)");
		err_flag = true;
	}

	if (i_flag == false)
	{
		fprintf(stderr, "Error! No input file specified.\n\n");
		err_flag = true;
	}

	if (k_flag == false)
	{
		fprintf(stderr, "Error! No key file specified.\n\n");
		err_flag = true;
	}

	if (p_flag == false)
	{
		fprintf(stderr, "Warning! Using default 'password'.\n\n");
	}

	if (o_flag == false && err_flag == false)	// no need to do this if we have errors
	{
		strcpy(gOutFileName, gInFileName);
		if (gOp == 1)	// encrypt
		{
			strcat(gOutFileName, ".enc");
		}
		if (gOp == 2)	// decrypt
		{
			strcat(gOutFileName, ".dec");
		}
	}

	if (err_flag)
	{
		usage(argv);
	}
	return;
} // parseCommandLine


void main(int argc, char *argv[])
{
#ifdef TEST_CODE
	char testData[] = "The big lazy brown FOX jumped 123 the 987 dog. Then he 8 a CHICKEN.";
	int numCAPS, numLow, numNonLetters;
	numCAPS = numLow = numNonLetters = 0;
	exCountLetters(testData, strlen(testData), &numCAPS, &numLow, &numNonLetters);
	printf("numCAPS=%d, numLow=%d, numNonLetters=%d\n", numCAPS, numLow, numNonLetters);
	exit(0);
#endif

	int length, resulti;

	// parse command line parameters
	parseCommandLine(argc, argv);		// sets global variables, checks input options for errors

	// open the input and output files
	gfptrIn = openInputFile(gInFileName);
	gfptrKey = openInputFile(gKeyFileName);
	gfptrOut = openOutputFile(gOutFileName);

	length = (size_t)strlen(gPassword);

	resulti = sha256(NULL, gPassword, length, gPasswordHash);		// get sha-256 hash of password
	if (resulti != 0)
	{
		fprintf(stderr, "Error! Password not hashed correctly.\n\n");
		exit(-1);
	}

	length = fread(gkey, 1, 65537, gfptrKey);
	if (length != 65537)
	{
		fprintf(stderr, "Error! Length of key file is not at least 65537.\n\n");
		exit(-1);
	}
	fclose(gfptrKey);
	gfptrKey = NULL;

	if (gOp == 1)	// encrypt
	{
		encryptFile(gfptrIn, gfptrOut);
	}
	else
	{
		decryptFile(gfptrIn, gfptrOut);
	}

	fclose(gfptrIn);
	fclose(gfptrOut);
	return;
} // main
