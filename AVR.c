// https://onlinedocs.microchip.com/pr/GUID-317042D4-BCCE-4065-BB05-AC4312DBC2C4-en-US-2/index.html?GUID-735C4A48-0970-4086-A5CA-89AC469956ED

#define UART_H_
#include <avr/eeprom.h>
#include <stdint.h>
#include <stdlib.h>
#include <avr/io.h>

#include <avr/interrupt.h>

#define F_CPU 8000000 // Рабочая частота контроллера
#define BAUD 9600L // Скорость обмена данными
#define UBRRL_val (F_CPU/ (BAUD *  16)) - 1

#define MEM_DATAADDR (0x0000)
#define FST_KEY_ADDR (0x0002)


typedef struct{
	uint16_t n;
	uint16_t e;
	uint16_t d;
} key_struct;


uint16_t seven_seg_data;
char cur_seg = 0;
enum {a_val, p_val} key_val = a_val;
unsigned char cur_key = 0; 
unsigned char max_key = 0;

//хранит режим, что отображаем ( E.xxx - 0, d.xxx - 1, S.xxx - 2, C.xxx - 3 (e - encrypt, d - decrypt, s - sign,c - check sign)
char dispay_stats = 0;
uint16_t bytes_enc = 0;
uint16_t bytes_dec = 0;
uint16_t sing_count = 0;
uint16_t sign_check_count = 0;




unsigned char dig_in_portc[10] = {0x3F, // 0
0x06,
0x5B,
0x4F,
0x66,
0x6D,
0x7D,
0x07,
0x7F,
0x6F};

unsigned char letter_in_portc[4] = {0xF9, // E.
0xDE, // d.
0xED, // S.
0xB9 // C.
};

//Хранит позицию последней тройки ключей в епроме, чтобы можно было пройтись
uint16_t next_key_addr;
char connected;

void init_UART();
void init_regs_and_intr();

void send_8(char value);
void send_16(uint16_t data);
char get_8(void);
uint16_t get_16(void);

void mem_init(); //Inits MEM_INFO from memory
void mem_store_key(key_struct key);
void mem_remove_key(uint16_t n, uint16_t e);
void mem_update_next_addr();
key_struct mem_find_key(uint16_t n, uint16_t e, uint16_t* addr);

void show_keys();


void connect();
void disconnect();
void add_key();
void remove_key();
void encrypt();
void decrypt();

uint64_t fast_pow(uint16_t n, uint16_t b, uint16_t e);

int main(void){
	init_regs_and_intr();
	init_UART(); 
	mem_init();

	connected = 0;

	while(1){
		switch(get_8()){
		case '+':
			connect();
			break;
		case '-':
			disconnect();
			break;
		case 'g':
			add_key();
			break;
		case 's':
			show_keys();
			break;
		case 'r'://удаление ключа
			remove_key();
			break;
		case 'e':
			encrypt();
			break;
		case 'd':
			decrypt();
			break;
		case 'c':
			digital_sign();
			break;
		case 'k':
			digital_sign_check();
			break;
		}
	}
}

void connect(){
	connected = 1;
	srand(TCNT2);
	mem_init();
	send_8('+');
}

void disconnect(){
	connected = 0;
	send_8('+');
}

void add_key(){
	if(!connected) 
		return;

	key_struct new_key = { 0 };
	new_key.n = get_16();
	new_key.e = get_16();
	new_key.d = get_16();

	mem_store_key(new_key);
	mem_update_next_addr();

	if(max_key == 0){
		if(key_val == a_val)
			seven_seg_data = new_key.n;
		else
			seven_seg_data = new_key.e;
	}
	max_key++;
	send_8('+');
}


void remove_key(){
	if(!connected) return;

	uint16_t n = get_16();
	uint16_t e = get_16();
	mem_remove_key(n, e);
	mem_update_next_addr();
}

void show_keys(){
	if(!connected) 
		return;

	uint16_t firstKey_addr = FST_KEY_ADDR;
	uint16_t lastKey_addr = next_key_addr;

	for(register int i = firstKey_addr; i < lastKey_addr; i+=sizeof(key_struct)){
		key_struct k;
		eeprom_read_block((void*)&k, (const void*)i, sizeof(key_struct));
		send_16(k.n);
		send_16(k.e);
		send_16(k.d);
	}

	send_16(0);
	send_16(0);
	send_16(0);
}

void digital_sign(){
	if(!connected) 
		return;
	uint16_t addr;
	key_struct k = mem_find_key(get_16(),get_16(),&addr);

	if(k.e == 0){
		send_8('-');
		return;
	}
   send_8('+');
   uint16_t d = k.d;  
   uint16_t n = k.n;
	send_16(d);
   unsigned char m = get_8();

	uint64_t sign = fast_pow(m, d, n);  // RSA encryption: c = m^e % n
	sing_count++;
	send_16((uint16_t)sign);
}

void digital_sign_check(){
	if(!connected) 
		return;
	uint16_t addr;
	key_struct k = mem_find_key(get_16(),get_16(),&addr);
	if(k.e == 0){
		send_8('-');
		return;
	}
	send_8('+');
	uint16_t e = k.e;  
   uint16_t n = k.n;


   uint16_t sign_check = get_16();	
   uint64_t hash = fast_pow(sign_check,e,n);  
   sign_check_count++;
	//send_8((char)hash);

   unsigned char hash_check = get_8();
   if((uint8_t)hash_check == (uint8_t)hash){
   	send_8('+');
  	return;
   }
   send_8('-');

}

void encrypt(){
	if (!connected)
       return;

    uint16_t addr;
    key_struct k = mem_find_key(get_16(), get_16(), &addr); // Достать из EEPROM
    if (k.e == 0) {  // Не найден
       send_8('-');
       return;
    }
    send_8('+');

    uint16_t e = k.e;  
    uint16_t n = k.n; 

    unsigned char m = 0;

    while ((m = get_8()) != 0xFF) {  // Until end of message
       uint64_t encrypted = fast_pow(m, e, n);  // RSA encryption: c = m^e % n
	    bytes_enc++;
       send_16((uint16_t)encrypted);
    }
}

void decrypt(){
	if (!connected)
       return;

    uint16_t addr;
    key_struct k = mem_find_key(get_16(), get_16(), &addr); // Get the key pair from EEPROM

    if (k.e == 0) {  // No key found
       send_8('-');
       return;
    }

    send_8('+');

    uint16_t d = k.d;  // Private exponent (d)
    uint16_t n = k.n;  // Modulus (n)

    uint16_t c = 0;  // Ciphertext

    while ((c = get_16()) != 0xFFFF) {  // Until end of message
       uint64_t decrypted = fast_pow(c, d, n);  // RSA decryption: m = c^d % n
	   bytes_dec++;
       send_8((char)decrypted);  // Send the decrypted character
    }
}

void init_UART() {
	//инициализация UART в режиме 9600/8-N-1

	UBRRL = UBRRL_val;; // Скорость передачи
	UBRRH = UBRRL_val >> 8;

	// Содержит флаги завершиения приема и передачи:
	//RXC TXC, UDRE - флаг свободности регистра UDR

	UCSRA = 0; 
	
	UCSRB = 1 << RXEN | 1 << TXEN; // Разрешения приема и передаачи
	UCSRC = 1 << URSEL | 1 << UCSZ0 | 1 << UCSZ1; // стоп-биты, бит четности, его проверка
}

void send_8(char value) {
	while(!(UCSRA & (1 << UDRE))); // Ожидаем когда очистится буфер передачи
	UDR = value; // Помещаем данные в буфер, начинаем передачу
}

void send_16(uint16_t data) {
	send_8((uint8_t)((data) & 0x00FF));
	send_8((uint8_t)((data >> 8) & 0x00FF));
}

// Получение байта
char get_8(void) {
	// Устанавливается, когда регистр свободен
	while(!(UCSRA & (1 << RXC)));
	return UDR;
}

uint16_t get_16(void) {
	uint16_t got = 0;

	got |= ((uint16_t)get_8()) & 0x00FF;
	got |= ((uint16_t)get_8() << 8) & 0xFF00;

	return got;
}

void mem_update_next_addr(){
	cli();
	eeprom_write_block((const void*)&next_key_addr, (void*)MEM_DATAADDR, sizeof(uint16_t));
	sei();
}

void mem_init(){
	cli();
	eeprom_busy_wait();
	eeprom_read_block((void*)&next_key_addr, (const void*)MEM_DATAADDR, sizeof(uint16_t));

	key_struct k;
	eeprom_read_block((void*)&k, (const void*)FST_KEY_ADDR, sizeof(key_struct));
	seven_seg_data = 0;

	if((next_key_addr - sizeof(uint16_t) - MEM_DATAADDR) % sizeof(key_struct) != 0){	
		next_key_addr = MEM_DATAADDR + sizeof(uint16_t);
		mem_update_next_addr();
	}

	max_key = (next_key_addr - FST_KEY_ADDR) / sizeof(key_struct);
	sei();
}

void mem_store_key(key_struct key){
	cli();
	eeprom_write_block((const void*)&key, (void*)next_key_addr, sizeof(key_struct));

	next_key_addr += sizeof(key_struct);
	mem_update_next_addr();
	sei();
}

key_struct mem_find_key(uint16_t n, uint16_t e, uint16_t* addr){
	cli();
	uint16_t first = FST_KEY_ADDR;
	uint16_t last = next_key_addr;

	for(uint16_t i = first; i < last; i += (uint16_t)sizeof(key_struct)){
		key_struct k;
		eeprom_read_block((void*)&k, (const void*)i, sizeof(key_struct));

		if(k.n == n && k.e == e) {
			*addr = i;
			sei();
			return k;
		}
	}

	key_struct k = { 0 };
	*addr = 0;
	sei();
	return k;
}

void mem_remove_key(uint16_t n, uint16_t e){
	cli();
	uint16_t addr;

	//поиск адреса удаляемого ключа
	mem_find_key(n, e, &addr);
	
	if(addr == 0){ //проверка на отсутствие ключей
		send_8('-');
		sei();
		return;
	}

	//все ключи после удалённого сдвигаются на адрес назад 
	//(включая ключ 0 0 0 по адресу next_key_addr)

	uint16_t remaining_keys_count = (next_key_addr - addr) / sizeof(key_struct) - 1;

	for(uint16_t i = 0; i <= remaining_keys_count; i++){
		key_struct tmp;
		//перенос ключа на место перед ним
		eeprom_read_block((void*)&tmp, (void*)(addr + sizeof(key_struct) * (i + 1)), sizeof(key_struct));
		eeprom_write_block((void*)&tmp, (void*)(addr + sizeof(key_struct) * i), sizeof(key_struct));
	}

	next_key_addr -= sizeof(key_struct);
	mem_update_next_addr();
	
	max_key--;
	if(cur_key <= max_key)
		cur_key--;

	send_8('+');
	sei();
}

uint64_t fast_pow(uint16_t n, uint16_t b, uint16_t e){
	uint64_t d = 1;
	uint64_t y = n;
	while(b > 0){
		if(b % 2 != 0)
			d = (d * y) % e;
		y = (y * y) % e;
		b = b / 2;
	}
	return d % e;
}

void init_regs_and_intr(){
	DDRA = 0b11111111; //на вывод
	DDRC = 0b11111111; //на вывод
	DDRD &= 0b11110011; //2 и 3 ножки на ввод(прерывания int0 и int1)

	MCUCR = 0b10001010; // Настройка прерываний int0 и int1 на условие 0/1
	GICR = 0b11000000; // Разрешение прерываний int0 и int1
	GIFR = 0b11000000; // Предотвращение срабатывания int0 и int1 при включении прерываний

	TIMSK |= (1 << TOIE2); //устанавливаем бит разрешения прерывания по переполнению таймера 2
	TCCR2 |= (1 << CS22); //Предделитель / 64

	TCNT2 = 0b00000000; // Обнуление счетчика
	sei(); 
}

ISR (TIMER2_OVF_vect){
	PORTC = 0;

	switch(dispay_stats){
	case 0:
		seven_seg_data = bytes_enc;
		break;
	case 1:
		seven_seg_data = bytes_dec;
		break;
	case 2:
		seven_seg_data = sing_count;
		break;
	case 3:
		seven_seg_data = sign_check_count;
		break;
	}	

	switch(cur_seg){
	case 0:
		PORTC = letter_in_portc[dispay_stats];
		PORTA = 0b00001000;
		break;
	case 1:
		PORTC = dig_in_portc[seven_seg_data  % 1000 / 100];
		PORTA = 0b00000100;
		break;
	case 2:
		PORTC = dig_in_portc[seven_seg_data  % 100 / 10];	
		PORTA = 0b00000010;
		break;
	case 3:
		PORTC = dig_in_portc[seven_seg_data  % 10];
		PORTA = 0b00000001;
		break;
	}

	++cur_seg;
	cur_seg %= 4;
}

ISR(INT0_vect){
	dispay_stats++;
	dispay_stats %= 4;

	// void eeprom_read_block(void *__dst, const void *__src, size_t __n)
}