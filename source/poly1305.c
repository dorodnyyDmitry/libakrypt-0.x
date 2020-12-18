#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>
#include <math.h>

const ak_uint32 CONSTANTS[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

struct chacha20_block{
    ak_uint32 key[8];
    ak_uint32 nonce[3];
    ak_uint32 count;

    ak_uint32 state[16];
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обратный побитовый сдвиг.

    @param to_roll структура, в которой необходимо выполнить сдвиг.

    @param nbits на сколько сдвигать.


    @return Возвращается структура с выполненным сдвигом.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint32 left_roll32(ak_uint32 to_roll, int nbits){
    return (to_roll << nbits) | (to_roll >> (32 - nbits));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция перемешивания полей в блоке ChaCha20.

    @param state массив полей, представляющий из себя состояние блока ChaCha20.

    @param a поле блока.
    @param b поле блока.
    @param c поле блока.
    @param d поле блока.

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static void quarter_round(ak_uint32 *state, int a, int b, int c, int d){
    state[a] += state[b]; state[d] = left_roll32(state[d] ^= state[a], 16);
    state[c] += state[d]; state[b] = left_roll32(state[b] ^= state[c], 12);
    state[a] += state[b]; state[d] = left_roll32(state[d] ^= state[a], 8);
    state[c] += state[d]; state[b] = left_roll32(state[b] ^= state[c], 7);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Выполняет поочередное перемешивание столбцов и диагоналей блока.

    @param state массив полей, представляющий из себя состояние блока ChaCha20.

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static void inner_block(ak_uint32 *state){
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация блока ChaCha20 по заданному ключу и одноразовому слову.

    @param block Указатель на блок ChaCha20, который необходимо инициализировать.
    @param key Массив полей, представляющих из себя ключ.
    @param nonce Массив полей, представляющих из себя одноразовое слово.
    @param block_count Значение счетчика блоков.

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static void block_init(struct chacha20_block *block,  ak_uint32 *key, ak_uint32 *nonce, ak_uint32 block_count){
    memcpy(block->key, &key, sizeof(key));
    memcpy(block->nonce, &nonce, sizeof(nonce));

    block->state[0] = CONSTANTS[0];
    block->state[1] = CONSTANTS[1];
    block->state[2] = CONSTANTS[2];
    block->state[3] = CONSTANTS[3];

    block->state[4] = key[0];
    block->state[5] = key[1];
    block->state[6] = key[2];
    block->state[7] = key[3];
    block->state[8] = key[4];
    block->state[9] = key[5];
    block->state[10] = key[6];
    block->state[11] = key[7];

    block->state[12] = block_count;

    block->state[13] = nonce[0];
    block->state[14] = nonce[1];
    block->state[15] = nonce[2];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вывод состояния блока ChaCha20.

    @param target Указатель на блок

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
void print_block(struct chacha20_block *target){
    printf("\n");

    for(int i = 0; i < 16; i+=4){
        printf("%s\t", ak_ptr_to_hexstr( &target->state[i+0], 4, ak_true));
        printf("%s\t", ak_ptr_to_hexstr( &target->state[i+1], 4, ak_true));
        printf("%s\t", ak_ptr_to_hexstr( &target->state[i+2], 4, ak_true));
        printf("%s\n", ak_ptr_to_hexstr( &target->state[i+3], 4, ak_true));
    }
    printf("\n");

}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление остатка от деления (для больших чисел не одинаковой длины).

    @param r Куда записать результат .
    @param u Вычет
    @param p Модуль
    @param u_size Размер вычета в блоках по 8 байт
    @param p_size Размер модуля в блоках по 8 байт

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
void my_modulo( ak_uint64 *r, ak_uint64 *u, ak_uint64 *p, const size_t u_size, const size_t p_size ){

    if(u[3] ==0){

        if(u[2] == 0){

            memcpy(r, u, sizeof(&u));
            return;
        }
        else{
            ak_mpzn_rem(u, u, p ,3);
            return;
        }
    }

    ak_uint64 test[3];
    ak_uint64 temp[3];

    ak_mpzn_set_hexstr(temp, 3, ak_ptr_to_hexstr(&u[1], 24, ak_true));


    const char* cringe = ak_ptr_to_hexstr(&u[0], 8, ak_true);
    char testt[5];
    ak_uint64 end1[4],end2[4],end3[4],end4[4];



    strncpy(testt, &cringe[0], 4);
    ak_mpzn_set_hexstr(end1, 4, testt);

    strncpy(testt, &cringe[4], 4);
    ak_mpzn_set_hexstr(end2, 4, testt);

    strncpy(testt, &cringe[8], 4);
    ak_mpzn_set_hexstr(end3, 4, testt);

    strncpy(testt, &cringe[12], 4);
    ak_mpzn_set_hexstr(end4, 4, testt);

    ak_mpzn_rem(test, temp, p, 3);

    ak_mpzn_mul_ui(test, test, 3, 65536);
    ak_mpzn_add(test, test, end1, 3);
    ak_mpzn_rem(test, test, p, 3);

    ak_mpzn_mul_ui(test, test, 3, 65536);
    ak_mpzn_add(test, test, end2, 3);
    ak_mpzn_rem(test, test, p, 3);

    ak_mpzn_mul_ui(test, test, 3, 65536);
    ak_mpzn_add(test, test, end3, 3);
    ak_mpzn_rem(test, test, p, 3);

    ak_mpzn_mul_ui(test, test, 3, 65536);
    ak_mpzn_add(test, test, end4, 3);
    ak_mpzn_rem(test, test, p, 3);

    memset(r, 0, 4*sizeof(ak_uint64));
    memcpy(r, test, sizeof(test));
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание блока ChaCha20 по заданному алгоритму (выполняется по 10 перемешиваний столбцов и диагоналей поочередно).

    @param new_block Указатель на блок
    @param key Массив полей, состаляющих ключ
    @param nonce Массив полей, состаляющих одноразовое слово
    @param count Значение счетчика блоков

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */

void init_chacha20_block(struct chacha20_block *new_block, ak_uint32 *key, ak_uint32 *nonce, int count){
    block_init(new_block, key, nonce, count);

    ak_uint32 initial_state[16];
    memcpy(initial_state, new_block->state, sizeof(new_block->state));


    for(int i = 0; i < 10; i++){
        inner_block(new_block->state);
    }

    for(int i = 0; i < 16; i++){
        new_block->state[i] += initial_state[i];
    }

}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Записывает параметр в массив uint_32 из строки

    @param strkey Указатель на строку с данными
    @param hexkey Указатель на массив uint_32, куда записать результат

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static void param_from_str(const char* strkey, ak_uint32* hexkey){
    ssize_t testsize = ak_hexstr_size(strkey);
    char temp[9];
    memset(temp, 0, 8);
    for(int i = 0; i < (int)ceil((double)testsize/4); i ++){
        strncpy(temp, &strkey[8*i], 8);
        temp[8] = '\0';
        ak_hexstr_to_ptr(temp, &hexkey[i], 4, ak_false);
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получает параметры для генерации тэга из блока ChaCha20

    @param chacha_block Указатель на блок ChaCha20
    @param r Массив uint32 куда записать первый параметр Poly1305
    @param s Массив uint32 куда записать второй параметр Poly1305

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static void get_poly1305_params(const struct chacha20_block *chacha_block, ak_uint32* r, ak_uint32* s){
    for(int i = 0; i < 4; i++){
        r[i] = chacha_block->state[i];
        s[i] = chacha_block->state[4+i];
    }
}


void string2hexString(char* input, char* output)
{
    int loop;
    int i;

    i=0;
    loop=0;

    while(input[loop] != '\0')
    {
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;
        i+=2;
    }

    output[i++] = '\0';
}

void clamp(ak_uint32 *r){
    r[0] &= 0x0ffffffc;
    r[1] &= 0x0ffffffc;
    r[2] &= 0x0ffffffc;
    r[3] &= 0x0ffffffc;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Генерирует тэг заданного сообщения по алгоритму Poly1305 с использованием псевдослучайных ключей из алгоритма ChaCha20

    @param str_message Сообщение произвольной длины
    @param str_key Строка с ключом для блока ChaCha20
    @param str_nonce строка с одноразовым словом для блока ChaCha20

    @return none.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
void poly1305_mac(char* str_message, char* str_key, char* str_nonce){
    ak_uint32 key[8];
    ak_uint32 nonce[3];

    size_t msg_size = strlen(str_message);
    char hex_message[msg_size*2];
    ak_uint32 message[msg_size*4];

    string2hexString(str_message, hex_message);


    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
    memset(message, 0, sizeof(message));

    param_from_str(str_key, key);
    param_from_str(str_nonce, nonce);
    param_from_str(hex_message, message);

    struct chacha20_block test_block;
    init_chacha20_block(&test_block, key, nonce, 0);

    ak_uint32 r[4];
    ak_uint32 s[4];

    memset(r, 0, sizeof(r));
    memset(s, 0, sizeof(s));

    get_poly1305_params(&test_block, r, s);

    clamp(r);

    ak_uint64 counter[4], mod[4], block[4];
    ak_uint64 long_s[4], long_r[4], padding[4];

    const char *r_str = ak_ptr_to_hexstr(s, 16, ak_true);
    const char *s_str = ak_ptr_to_hexstr(r, 16, ak_true);


    //testing purposes
    /*const char *s_str = "1bf54941aff6bf4afdb20dfb8a800301";
    const char *r_str = "806d5400e52447c036d555408bed685";*/


    ak_mpzn_set_hexstr(long_s, 4, s_str);
    ak_mpzn_set_hexstr(long_r, 4, r_str);
    ak_mpzn_set_hexstr(mod, 4, "3fffffffffffffffffffffffffffffffb");
    ak_mpzn_set_hexstr(padding, 4, "100000000000000000000000000000000");
    ak_mpzn_set_ui(counter, 4, 0);

    int iters = (int)ceil((double)strlen(str_message)/16);

    for(int i = 0; i < iters; i++){
        if(i == iters - 1){
            char test[] = "00000000000000000000000000000000";
            test[31 - 2*strlen(&str_message[16*i])] = '1';
            ak_mpzn_set_hexstr(padding, 4, test);

        }
        else{
            ak_mpzn_set_hexstr(padding, 4, "100000000000000000000000000000000");
        }

        ak_mpzn_set_hexstr(block, 4, ak_ptr_to_hexstr(&message[4*i], 16, ak_true));

        ak_mpzn_add(block, block, padding, 4);

        //const char *temp = ak_ptr_to_hexstr(block, 32, ak_true);

        ak_mpzn_add(counter, counter, block, 4);

        //const char *temp2 = ak_ptr_to_hexstr(counter, 32, ak_true);

        ak_mpzn_set_hexstr(long_r, 4, r_str);
        ak_mpzn_mul(counter, counter, long_r, 4);

        my_modulo(counter, counter, mod, 4, 2);

    }

    ak_mpzn_add(counter, counter, long_s, 4);

    printf("final tag\t%s\n", ak_ptr_to_hexstr(counter, 16, ak_false));

}
