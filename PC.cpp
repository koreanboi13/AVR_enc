#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <conio.h>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <iostream>
#include <cmath>
#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <algorithm>
#include <functional> 
using namespace std;


struct key_struct{
	uint16_t n; //n
	uint16_t e; //e
	uint16_t d; //d
};


HANDLE com_handle;


void close_com();
void err_handle(const char* func, int ret);
int init_com(const char* com_id);

bool send_8(unsigned char data);
bool send_16(uint16_t data);
unsigned char get_8();
uint16_t get_16();

key_struct enter_key();
char menu();
char generate_key();
char add_key_manually();
void remove_key();
void remove_all_keys();
void show_all_keys();
void encrypt();
void decrypt();
char disconnect();
void digital_sign();
void digital_sign_check();
uint16_t randint(uint16_t min, uint16_t max);
char gcd(uint16_t n);
uint16_t rand_primal(uint16_t min, uint16_t max);


int main(void) {
	setlocale(LC_ALL, "rus");

	srand((unsigned)time(NULL));

	if (init_com("COM3")) {
		cout << "No connection." << endl;
		return -1;
	}

	while(1){
		cout << "Trying to connect..." << endl;

		send_16(0xFFFF); 

		send_8('+');
		Sleep(500);

		if(get_8() == '+'){
			cout << "Connected." << endl;

			if (menu())
				break;
		}

	}
}


uint16_t randint(uint16_t min, uint16_t max) {
	return (uint16_t)min + (uint16_t)((double)rand() / (RAND_MAX + 1) * (max - min + 1));
}

char gcd(uint16_t n){
	for (uint16_t i = 2; i <= sqrt(n); i++)
	    if (n % i == 0)
	        return -1;

	return 0;
}

uint16_t rand_primal(uint16_t min, uint16_t max){
	uint16_t n;
	do{
		n = randint(min, max);
	}while(gcd(n));

	return n;
}

void close_com() { 
	CloseHandle(com_handle);
	cout << "COM closed." << endl;
}

void err_handle(const char* func, int ret){
	DWORD err = GetLastError();
	if (err == 0) return;

	LPSTR errmsg = NULL;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&errmsg, 0, NULL);

	cout << "Error(" << func << "): " << ret << " - " << errmsg << endl;
	LocalFree(errmsg);
}

int init_com(const char* com_id) {
	HANDLE serial = CreateFile((LPSTR)com_id, GENERIC_READ | GENERIC_WRITE, 0, 0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, 0);
	if (serial == INVALID_HANDLE_VALUE) {
		err_handle("CreateFile()", -1);
		return -1;
	}

	DCB params = { 0 };
	params.DCBlength = sizeof(params);
	if (!GetCommState(serial, &params)) {
		err_handle("GetCommState()", 0);
		return -1;
	}

	params.BaudRate = CBR_9600;
	params.ByteSize = 8;
	params.StopBits = ONESTOPBIT;
	params.Parity = NOPARITY;

	cout << "COM opened." << endl;

	if (!SetCommState(serial, &params)) {
		err_handle("SetCommState()", 0);
		return -1;
	}

	com_handle = serial;

	return 0;
}

bool send_8(unsigned char data){
	DWORD sent = 0;
	BOOL ret = false;
	if (!(ret = WriteFile(com_handle, &data, 1, &sent, 0)))
		err_handle("Send.", 0);

	return ret;
}

bool send_16(uint16_t data){
	bool ret = true;

	ret &= send_8(data& 0x00FF);
	ret &= send_8((data >> 8) & 0x00FF);

	return ret;
}

unsigned char get_8(){
	unsigned char got = 0;
	DWORD got_len = 0;
	if (!ReadFile(com_handle, &got, 1, &got_len, 0))
		err_handle("Get.", 0);

	return got;
}

uint16_t get_16(){
	uint16_t got = 0;

	got |= ((uint16_t)get_8()) & 0x00FF;
	got |= (((uint16_t)get_8()) << 8) & 0xFF00;

	return got;
}

char menu() {
	int action;
	while (1) {
		system("cls");

		cout << "RSA encryption system:" << endl;

		cout << "1)Add new key manually" << endl;
		cout << "2)Remove key" << endl;
		cout << "3)Remove all keys" << endl;
		cout << "4)Show all keys" << endl;
		cout << "5)Encrypt file" << endl;
		cout << "6)Decrypt file" << endl;
		cout << "7)Reconnect" << endl;
		cout << "8)sign" << endl;
		cout << "9)digital_sign_check" << endl;
		cout << "10)Exit" << endl;
		cout << ": ";

		cin >> action;

		switch (action) {
		case 1:
			add_key_manually();
			break;
		case 2:
			remove_key();
			break;
		case 3:
			remove_all_keys();
			break;
		case 4:
			show_all_keys();
			break;
		case 5:
			encrypt();
			break;
		case 6:
			decrypt();
			break;
		case 7:
			
			disconnect();
			break;
		case 8:
			digital_sign();
			break;
		case 9:
			digital_sign_check();
			break;
		case 10:
			
			disconnect();
			close_com();
			return -1;
		}

		cout << "Press any key to continue..." << endl;
		_getch();
	}
}

char add_key_manually() {
	send_8('g');

	struct key_struct k;

	cout << "Enter n: ";
	cin >> k.n;
	cout << "Enter e: ";
	cin >> k.e;
	cout << "Enter d: ";
	cin >> k.d;

	send_16(k.n);
	send_16(k.e); 
	send_16(k.d); 

	Sleep(500);


	if(get_8() == '+'){
		cout << "New key has been added." << endl;
		cout << "N: " << k.n << ". E: " << k.e << ". D: " << k.d << "." << endl;

		return 0;
	}

	cout << "Error." << endl;

	return -1;
}
uint8_t hash_function(const unsigned char* data, size_t len) {
    uint8_t hash = 0;

    // Применяем XOR для каждого байта данных
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];              // XOR каждого байта
        hash = (hash << 5) | (hash >> 3); // Циклический сдвиг
    }

    return hash;
}



void remove_key() {
	struct key_struct k;

	cout << "Enter n: ";
	cin >> k.n;
	cout << "Enter e: ";
	cin >> k.e;

	cout << "Removing key..." << endl;

	send_8('r');
	send_16(k.n);
	send_16(k.e);

	if(get_8() == '+')
		cout << "Removed successfully." << endl;
	else
		cout << "Error while removing." << endl;
}
void digital_sign(){
	struct key_struct k;
	cout << "Enter n: ";
	cin >> k.n;
	cout << "Enter e: ";
	cin >> k.e;

	send_8('c');

	send_16(k.n);
	send_16(k.e); 

	if(get_8() == '-'){
		cout << "Invalid key";
		return;
	}
	std::cout << get_16() << std::endl;
	FILE *inp, *enc;
    unsigned char *data;
    char filename[256];
    long file_size;
    
   	cout << "File to sign: ";
    cin>> filename;

    inp = fopen(filename, "rb");
    if (inp == NULL) {
        cout<<"Cannot open file \n" << filename;
        send_8(0xFF);
        return;
    }

    fseek(inp, 0, SEEK_END);
    file_size = ftell(inp);
    rewind(inp);

    data = (unsigned char *)malloc(file_size);
    if (data == NULL) {
        cout<<"Memory error\n";
        send_8(0xFF);
        fclose(inp);
        return;
    }

    fread(data, 1, file_size, inp);
    fclose(inp);

    cout<<"File to store sign: ";
    cin>> filename;

    enc = fopen(filename, "wb");
    if (enc == NULL) {
        cout << "Cannot open file \n", filename;
        send_8(0xFF);
        free(data);
        return;
    }
    

    for (long i = 0; i < file_size; i++) {
        if (data[i] == '\r') {
            continue;
        }
    }
    uint8_t hash = hash_function(data, file_size);
 	send_8(hash);  
    uint16_t encByte = get_16(); 
    std::cout << encByte << std::endl;
    fwrite((char*)&encByte + 1, 1, 1, enc);
    fwrite((char*)&encByte, 1, 1, enc);

    free(data);
    fclose(enc);

    
	send_8(0xFF);
	cout << "Successfully signded.\n";

}

void digital_sign_check(){
	struct key_struct k;
	cout << "Enter n: ";
	cin >> k.n;
	cout << "Enter e: ";
	cin >> k.e;

	send_8('k');

	send_16(k.n);
	send_16(k.e); 

	if(get_8() == '-'){
		cout << "Invalid key";
		return;
	}

	FILE *hash_file, *signature_file;
    uint16_t signature_byte;
    unsigned char *data;
    char filename[256];
    char signature_filename[256];
    long file_size;

    cout<<"Enter the filename containing the signature: ";
    cin>> signature_filename;

 
    signature_file = fopen(signature_filename, "r");
    if (signature_file == NULL) {
        cout << "Cannot open file \n" << signature_filename;
        send_8(0xFF); 
        return;
    }

    uint16_t buf;
    fread((char*)&buf+1, sizeof(char), 1, signature_file);
    printf("%d\n",buf);
    fread((char*)&buf,sizeof(char),1,signature_file);
	printf("%d\n",buf);
	send_16(buf);
	fclose(signature_file);

    cout << "Enter the filename that was signed: ";
   	cin>> filename;

    hash_file = fopen(filename, "rb");
    if (hash_file == NULL) {
        cout << "Cannot open file %s\n"<< filename;
        send_8(0xFF);
        return;
    }

    fseek(hash_file, 0, SEEK_END);
    file_size = ftell(hash_file);
    rewind(hash_file);

    data = (unsigned char *)malloc(file_size);
    if (data == NULL) {
        cout << "Memory error\n";
        send_8(0xFF);
        fclose(hash_file);
        return;
    }

    fread(data, 1, file_size, hash_file);
    fclose(hash_file);

    for (long i = 0; i < file_size; i++) {
        if (data[i] == '\r') {
            continue;
        }
    }
    uint8_t hash = hash_function(data, file_size);
 	send_8(hash);  
    free(data);
    if(get_8() == '+')
    	cout << "GOOD!\n";
    else
   		cout << "BAD!\n";
    send_8(0xFF);
}

void remove_all_keys() {
	send_8('s');

	key_struct keys_arr[1024];

	int i = 0;
	while (1) {
		uint16_t n = get_16();
		uint16_t e = get_16();
		uint16_t d = get_16();

		if (n == 0 && e == 0) break;

		keys_arr[i].n = n;
		keys_arr[i].e = e;
		keys_arr[i].d = d;

		i++;
	}
	i--;

	if (i == 0) {
		cout << "No keys have been added yet." << endl;
		return;
	}

	cout << "Keys have been read." << endl;

	for(i; i >= 0; i--) {
		send_8('r');

		send_16(keys_arr[i].n);
		send_16(keys_arr[i].e);

		if(get_8() == '+')
			cout << "Key " << i << " removed successfully." << endl;
		else
			cout << "Error while removing." << endl;
	}
}

void show_all_keys() {
	cout << "List of all stored keys:" << endl;

	send_8('s');
	int i = 0;

	while (1) {
		uint16_t n = get_16();
		uint16_t e = get_16();
		uint16_t d = get_16();
		if (n == 0 && e == 0) break;

		cout << i << ":\t n=" << n << "; e=" << e << "; d=" << d << endl;
		i++;
	}

	if (i == 0) cout << "No keys have been added yet." << endl;
}

void encrypt() {
	key_struct k;
	cout << "Enter n: ";
	cin >> k.n;

	cout << "Enter e: ";
	cin >> k.e;

	send_8('e');
	send_16(k.n);
	send_16(k.e);


	if(get_8() == '-'){
		cout << "Invalid key." << endl;
		return;
	}

	FILE *inp, *enc;
    unsigned char *data;
    char filename[256];
    long file_size;
    
    cout << "File to encrypt: ";
    cin>> filename;

    inp = fopen(filename, "rb");
    if (inp == NULL) {
        cout << "Cannot open file %s\n"<<filename;
        send_8(0xFF);
        return;
    }

    fseek(inp, 0, SEEK_END);
    file_size = ftell(inp);
    rewind(inp);

    data = (unsigned char *)malloc(file_size);
    if (data == NULL) {
        cout << "Memory error\n";
        send_8(0xFF);
        fclose(inp);
        return;
    }

    fread(data, 1, file_size, inp);
    fclose(inp);

    cout << "File to store encrypted data: ";
    cin>> filename;

    enc = fopen(filename, "wb");
    if (enc == NULL) {
        cout << "Cannot open file %s\n" << filename;
        send_8(0xFF);
        free(data);
        return;
    }

    for (long i = 0; i < file_size; i++) {
        if (data[i] == '\r') {
            continue;
        }

        send_8(data[i]);  
        uint16_t encByte = get_16(); 

        fwrite((char*)&encByte + 1, 1, 1, enc);
        fwrite((char*)&encByte, 1, 1, enc);

        cout << "Encrypting: \r" << (i + 1) * 100 / file_size;
    }

    free(data);
    fclose(enc);

    
	send_8(0xFF);
	cout << "Successfully encrypted.\n";
	
}

void decrypt() {
	key_struct k;
	cout << "Enter n: ";
	cin >> k.n;

	cout << "Enter e: ";
	cin >> k.e;

	send_8('d');
	send_16(k.n);
	send_16(k.e);

	if(get_8() == '-'){
		cout << "Invalid key." << endl;
		return;
	}

	FILE *enc, *dec;
    uint16_t *data;
    char filename[256];
    long file_size;
    
   	cout << "File to decrypt: ";
    cin>>filename;

    enc = fopen(filename, "rb");
    if (enc == NULL) {
        cout<< "Cannot open file \n" << filename;
        send_16(0xFFFF);
        return;
    }

    fseek(enc, 0, SEEK_END);
    file_size = ftell(enc);
    rewind(enc);

    if (file_size % 2 != 0) {
        cout << "File size error\n";
        send_16(0xFFFF);
        fclose(enc);
        return;
    }

    data = (uint16_t *)malloc(file_size / 2 * sizeof(uint16_t));
    if (data == NULL) {
        cout<< "Memory error\n";
        fclose(enc);
        return;
    }

    for (int i = 0; i < file_size / 2; i++) {
	    unsigned char high_byte, low_byte;
	    fread(&high_byte, 1, 1, enc); 
	    fread(&low_byte, 1, 1, enc);  

	    data[i] = (uint16_t)((high_byte << 8) | low_byte);
	}

    fclose(enc);

    cout << "Enter filename to store decrypted data: ";
    cin >>  filename;

    dec = fopen(filename, "wb");
    if (dec == NULL) {
        cout << "Cannot open file \n" << filename;
        send_16(0xFFFF);
        free(data);
        return;
    }

    int len = file_size / 2;
    for (int i = 0; i < len; i++) {
        send_16(data[i]); 
        unsigned char decByte = get_8(); 

        fwrite(&decByte, 1, 1, dec);

        cout<< "Decrypting: \r"<< (i + 1) * 100 / len;
    }

    send_16(0xFFFF);

    free(data);
    fclose(dec);

    cout<< "Successfully decrypted.\n";
}

char disconnect() {
	cout << "Trying to disconnect..." << endl;
	send_8('-');
	Sleep(500);

	if(get_8() == '+'){
		cout << "Disconnected." << endl;
		return 0;
	}

	return -1;
}