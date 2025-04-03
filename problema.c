/**
 * @file problema.c
 * @brief 프로블레마(Problema) 암호화 알고리즘 구현
 *
 * 이 파일은 프로블레마 암호화 알고리즘의 핵심 기능을 구현합니다.
 * 프로블레마는 애니그마 알고리즘을 개선하고 AES 암호화 알고리즘과 결합한
 * 한글/영어 교차지원이 가능한 새로운 암호화 알고리즘입니다.
 * 해당 알고리즘은 보안전공 학부생의 실습 목적으로 제작되었으며, 실사용을 권장하지 않습니다.
 */

#include "problema.h"
#include <string.h>
#include <stdio.h>

/* 디버그 모드 플래그 */
static bool debug_mode = false;

/* 오류 코드 */
#define PROBLEMA_SUCCESS 0
#define PROBLEMA_ERROR_NULL_POINTER -1
#define PROBLEMA_ERROR_INVALID_KEY -2
#define PROBLEMA_ERROR_NOT_INITIALIZED -3
#define PROBLEMA_ERROR_BUFFER_TOO_SMALL -4
#define PROBLEMA_ERROR_INVALID_UTF8 -5

/* 내부 함수 선언 */
static void init_rotors(ProblemaContext *ctx);
static void init_plugboard(ProblemaContext *ctx);
static void init_aes_components(ProblemaContext *ctx);
static void rotate_rotors(ProblemaContext *ctx);
static unicode_t apply_plugboard(ProblemaContext *ctx, unicode_t input);
static unicode_t apply_rotors_forward(ProblemaContext *ctx, unicode_t input);
static unicode_t apply_rotors_backward(ProblemaContext *ctx, unicode_t input);
static void apply_aes_transformation(ProblemaContext *ctx, byte_t *block);
static void apply_inverse_aes_transformation(ProblemaContext *ctx, byte_t *block);
static void update_feedback(ProblemaContext *ctx, const byte_t *block);
static void debug_print_state(const char *label, const byte_t *data, size_t len);
static void debug_print_unicode(const char *label, unicode_t code);

/* 오류 메시지 */
static const char *error_messages[] = {
    "성공",
    "NULL 포인터 오류",
    "유효하지 않은 키",
    "초기화되지 않은 컨텍스트",
    "버퍼 크기 부족",
    "유효하지 않은 UTF-8 시퀀스"};

/**
 * @brief 프로블레마 컨텍스트 초기화
 */
int problema_init(ProblemaContext *ctx, const byte_t *key)
{
    if (ctx == NULL || key == NULL)
    {
        return PROBLEMA_ERROR_NULL_POINTER;
    }

    /* 키 복사 */
    memcpy(ctx->key, key, PROBLEMA_KEY_SIZE);

    /* 컴포넌트 초기화 */
    init_rotors(ctx);
    init_plugboard(ctx);
    init_aes_components(ctx);

    /* 피드백 초기화 */
    memset(ctx->feedback, 0, PROBLEMA_BLOCK_SIZE);
    memset(ctx->initial_feedback, 0, PROBLEMA_BLOCK_SIZE);

    /* 기본값은 암호화 모드 */
    ctx->encrypt_mode = true;

    ctx->initialized = true;

    if (debug_mode)
    {
        printf("[DEBUG] 프로블레마 컨텍스트 초기화 완료\n");
    }

    return PROBLEMA_SUCCESS;
}

/**
 * @brief 프로블레마 컨텍스트 해제
 */
void problema_cleanup(ProblemaContext *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    /* 민감한 데이터 제로화 */
    memset(ctx->key, 0, PROBLEMA_KEY_SIZE);
    memset(ctx->feedback, 0, PROBLEMA_BLOCK_SIZE);

    /* 초기화 상태 재설정 */
    ctx->initialized = false;

    if (debug_mode)
    {
        printf("[DEBUG] 프로블레마 컨텍스트 해제 완료\n");
    }
}

/**
 * @brief 단일 유니코드 문자 암호화
 */
unicode_t problema_encrypt_char(ProblemaContext *ctx, unicode_t input)
{
    if (ctx == NULL || !ctx->initialized)
    {
        return input; /* 오류 시 원본 반환 */
    }

    /* 암호화 모드로 설정 */
    ctx->encrypt_mode = true;

    if (debug_mode)
    {
        debug_print_unicode("암호화 전 문자", input);
    }

    /* 암호화 과정 */
    unicode_t output = input;

    /* 1. 플러그보드 적용 */
    output = apply_plugboard(ctx, output);
    if (debug_mode)
    {
        debug_print_unicode("플러그보드 적용 후", output);
    }

    /* 2. 순방향 로터 적용 */
    output = apply_rotors_forward(ctx, output);
    if (debug_mode)
    {
        debug_print_unicode("순방향 로터 적용 후", output);
    }

    /* 3. 로터 회전 */
    rotate_rotors(ctx);

    /* 4. 역방향 로터 적용 */
    output = apply_rotors_backward(ctx, output);
    if (debug_mode)
    {
        debug_print_unicode("역방향 로터 적용 후", output);
    }

    /* 5. 피드백 적용 (문자의 바이트 표현을 XOR) */
    byte_t char_bytes[4] = {0};
    char_bytes[0] = (output >> 24) & 0xFF;
    char_bytes[1] = (output >> 16) & 0xFF;
    char_bytes[2] = (output >> 8) & 0xFF;
    char_bytes[3] = output & 0xFF;

    /* 피드백 상태 저장 (첫 번째 문자인 경우) */
    if (memcmp(ctx->feedback, ctx->initial_feedback, PROBLEMA_BLOCK_SIZE) == 0)
    {
        memcpy(ctx->initial_feedback, ctx->feedback, PROBLEMA_BLOCK_SIZE);
    }

    for (int i = 0; i < 4; i++)
    {
        char_bytes[i] ^= ctx->feedback[i % PROBLEMA_BLOCK_SIZE];
    }

    output = ((unicode_t)char_bytes[0] << 24) |
             ((unicode_t)char_bytes[1] << 16) |
             ((unicode_t)char_bytes[2] << 8) |
             char_bytes[3];

    /* 피드백 상태 업데이트 */
    for (int i = 0; i < 4; i++)
    {
        ctx->feedback[i % PROBLEMA_BLOCK_SIZE] = char_bytes[i];
    }

    if (debug_mode)
    {
        debug_print_unicode("암호화 후 문자", output);
    }

    return output;
}

/**
 * @brief 단일 유니코드 문자 복호화
 */
unicode_t problema_decrypt_char(ProblemaContext *ctx, unicode_t input)
{
    if (ctx == NULL || !ctx->initialized)
    {
        return input; /* 오류 시 원본 반환 */
    }

    /* 복호화 모드로 설정 */
    ctx->encrypt_mode = false;

    if (debug_mode)
    {
        debug_print_unicode("복호화 전 문자", input);
    }

    /* 복호화 과정 (암호화의 역순) */
    unicode_t output = input;

    /* 1. 현재 입력 저장 (피드백 업데이트용) */
    byte_t input_bytes[4] = {0};
    input_bytes[0] = (input >> 24) & 0xFF;
    input_bytes[1] = (input >> 16) & 0xFF;
    input_bytes[2] = (input >> 8) & 0xFF;
    input_bytes[3] = input & 0xFF;

    /* 2. 피드백 적용 (문자의 바이트 표현을 XOR) */
    byte_t char_bytes[4] = {0};
    char_bytes[0] = (output >> 24) & 0xFF;
    char_bytes[1] = (output >> 16) & 0xFF;
    char_bytes[2] = (output >> 8) & 0xFF;
    char_bytes[3] = output & 0xFF;

    for (int i = 0; i < 4; i++)
    {
        char_bytes[i] ^= ctx->feedback[i % PROBLEMA_BLOCK_SIZE];
    }

    output = ((unicode_t)char_bytes[0] << 24) |
             ((unicode_t)char_bytes[1] << 16) |
             ((unicode_t)char_bytes[2] << 8) |
             char_bytes[3];

    /* 3. 피드백 상태 업데이트 (다음 문자를 위해) */
    for (int i = 0; i < 4; i++)
    {
        ctx->feedback[i % PROBLEMA_BLOCK_SIZE] = input_bytes[i];
    }

    /* 4. 역방향 로터 적용 (암호화의 순방향 로터에 해당) */
    output = apply_rotors_backward(ctx, output);
    if (debug_mode)
    {
        debug_print_unicode("역방향 로터 적용 후", output);
    }

    /* 5. 로터 회전 */
    rotate_rotors(ctx);

    /* 6. 순방향 로터 적용 (암호화의 역방향 로터에 해당) */
    output = apply_rotors_forward(ctx, output);
    if (debug_mode)
    {
        debug_print_unicode("순방향 로터 적용 후", output);
    }

    /* 7. 플러그보드 적용 */
    output = apply_plugboard(ctx, output);
    if (debug_mode)
    {
        debug_print_unicode("플러그보드 적용 후", output);
    }

    if (debug_mode)
    {
        debug_print_unicode("복호화 후 문자", output);
    }

    return output;
}

/**
 * @brief 블록 암호화
 */
void problema_encrypt_block(ProblemaContext *ctx, const byte_t *input, byte_t *output)
{
    if (ctx == NULL || input == NULL || output == NULL || !ctx->initialized)
    {
        return;
    }

    if (debug_mode)
    {
        debug_print_state("암호화 전 블록", input, PROBLEMA_BLOCK_SIZE);
    }

    /* 입력 블록 복사 */
    memcpy(output, input, PROBLEMA_BLOCK_SIZE);

    /* 1. 피드백과 XOR */
    for (int i = 0; i < PROBLEMA_BLOCK_SIZE; i++)
    {
        output[i] ^= ctx->feedback[i];
    }

    /* 2. AES 변환 적용 */
    apply_aes_transformation(ctx, output);

    /* 3. 피드백 업데이트 */
    update_feedback(ctx, output);

    if (debug_mode)
    {
        debug_print_state("암호화 후 블록", output, PROBLEMA_BLOCK_SIZE);
    }
}

/**
 * @brief 블록 복호화
 */
void problema_decrypt_block(ProblemaContext *ctx, const byte_t *input, byte_t *output)
{
    if (ctx == NULL || input == NULL || output == NULL || !ctx->initialized)
    {
        return;
    }

    if (debug_mode)
    {
        debug_print_state("복호화 전 블록", input, PROBLEMA_BLOCK_SIZE);
    }

    /* 입력 블록 복사 및 임시 저장 (피드백 업데이트용) */
    byte_t temp_block[PROBLEMA_BLOCK_SIZE];
    memcpy(temp_block, input, PROBLEMA_BLOCK_SIZE);
    memcpy(output, input, PROBLEMA_BLOCK_SIZE);

    /* 1. 역 AES 변환 적용 */
    apply_inverse_aes_transformation(ctx, output);

    /* 2. 피드백과 XOR */
    for (int i = 0; i < PROBLEMA_BLOCK_SIZE; i++)
    {
        output[i] ^= ctx->feedback[i];
    }

    /* 3. 피드백 업데이트 */
    update_feedback(ctx, temp_block);

    if (debug_mode)
    {
        debug_print_state("복호화 후 블록", output, PROBLEMA_BLOCK_SIZE);
    }
}

/**
 * @brief UTF-8 문자열 암호화
 */
int problema_encrypt(ProblemaContext *ctx, const byte_t *input, size_t input_len,
                     byte_t *output, size_t output_size, size_t *output_len)
{
    if (ctx == NULL || input == NULL || output == NULL || output_len == NULL)
    {
        return PROBLEMA_ERROR_NULL_POINTER;
    }

    if (!ctx->initialized)
    {
        return PROBLEMA_ERROR_NOT_INITIALIZED;
    }

    /* 암호화 모드로 설정 */
    ctx->encrypt_mode = true;

    /* 초기 상태 저장 */
    byte_t initial_rotors_pos[PROBLEMA_NUM_ROTORS];
    for (int r = 0; r < PROBLEMA_NUM_ROTORS; r++)
    {
        initial_rotors_pos[r] = ctx->rotors[r].position;
    }

    /* 피드백 초기화 */
    memset(ctx->feedback, 0, PROBLEMA_BLOCK_SIZE);
    memset(ctx->initial_feedback, 0, PROBLEMA_BLOCK_SIZE);

    /* UTF-8 입력을 유니코드로 변환 */
    unicode_t *unicode_buffer = (unicode_t *)malloc(input_len * sizeof(unicode_t));
    if (unicode_buffer == NULL)
    {
        return PROBLEMA_ERROR_BUFFER_TOO_SMALL;
    }

    size_t unicode_len = 0;
    int result = utf8_to_unicode(input, input_len, unicode_buffer, input_len, &unicode_len);
    if (result != PROBLEMA_SUCCESS)
    {
        free(unicode_buffer);
        return result;
    }

    /* 각 유니코드 문자 암호화 */
    for (size_t i = 0; i < unicode_len; i++)
    {
        unicode_buffer[i] = problema_encrypt_char(ctx, unicode_buffer[i]);
    }

    /* 암호화된 유니코드를 UTF-8로 변환 */
    result = unicode_to_utf8(unicode_buffer, unicode_len, output, output_size, output_len);

    free(unicode_buffer);
    return result;
}

/**
 * @brief UTF-8 문자열 복호화
 */
int problema_decrypt(ProblemaContext *ctx, const byte_t *input, size_t input_len,
                     byte_t *output, size_t output_size, size_t *output_len)
{
    if (ctx == NULL || input == NULL || output == NULL || output_len == NULL)
    {
        return PROBLEMA_ERROR_NULL_POINTER;
    }

    if (!ctx->initialized)
    {
        return PROBLEMA_ERROR_NOT_INITIALIZED;
    }

    /* 복호화 모드로 설정 */
    ctx->encrypt_mode = false;

    /* 초기 상태 저장 */
    byte_t initial_rotors_pos[PROBLEMA_NUM_ROTORS];
    for (int r = 0; r < PROBLEMA_NUM_ROTORS; r++)
    {
        initial_rotors_pos[r] = ctx->rotors[r].position;
    }

    /* 피드백 초기화 - 암호화와 동일한 초기 상태 사용 */
    memset(ctx->feedback, 0, PROBLEMA_BLOCK_SIZE);

    /* UTF-8 입력을 유니코드로 변환 */
    unicode_t *unicode_buffer = (unicode_t *)malloc(input_len * sizeof(unicode_t));
    if (unicode_buffer == NULL)
    {
        return PROBLEMA_ERROR_BUFFER_TOO_SMALL;
    }

    size_t unicode_len = 0;
    int result = utf8_to_unicode(input, input_len, unicode_buffer, input_len, &unicode_len);
    if (result != PROBLEMA_SUCCESS)
    {
        free(unicode_buffer);
        return result;
    }

    /* 각 유니코드 문자 복호화 */
    for (size_t i = 0; i < unicode_len; i++)
    {
        unicode_buffer[i] = problema_decrypt_char(ctx, unicode_buffer[i]);
    }

    /* 복호화된 유니코드를 UTF-8로 변환 */
    result = unicode_to_utf8(unicode_buffer, unicode_len, output, output_size, output_len);

    free(unicode_buffer);
    return result;
}

/**
 * @brief 디버그 모드 설정
 */
void problema_set_debug(bool enable)
{
    debug_mode = enable;
    if (debug_mode)
    {
        printf("[DEBUG] 디버그 모드 활성화\n");
    }
}

/**
 * @brief 오류 코드에 대한 설명 문자열 반환
 */
const char *problema_error_string(int error_code)
{
    error_code = -error_code;
    if (error_code >= 0 && error_code < (int)(sizeof(error_messages) / sizeof(error_messages[0])))
    {
        return error_messages[error_code];
    }
    return "알 수 없는 오류";
}

/* UTF-8 관련 유틸리티 함수 구현 */

/**
 * @brief UTF-8 문자열을 유니코드 코드 포인트 배열로 변환
 */
int utf8_to_unicode(const byte_t *utf8, size_t utf8_len,
                    unicode_t *unicode, size_t unicode_size, size_t *unicode_len)
{
    if (utf8 == NULL || unicode == NULL || unicode_len == NULL)
    {
        return PROBLEMA_ERROR_NULL_POINTER;
    }

    size_t i = 0, j = 0;

    while (i < utf8_len && j < unicode_size)
    {
        if ((utf8[i] & 0x80) == 0)
        {
            /* ASCII 문자 (1바이트) */
            unicode[j++] = utf8[i++];
        }
        else if ((utf8[i] & 0xE0) == 0xC0)
        {
            /* 2바이트 UTF-8 시퀀스 */
            if (i + 1 >= utf8_len || (utf8[i + 1] & 0xC0) != 0x80)
            {
                if (debug_mode)
                {
                    printf("[DEBUG] 유효하지 않은 2바이트 UTF-8 시퀀스: %02X %02X\n",
                           utf8[i], (i + 1 < utf8_len) ? utf8[i + 1] : 0);
                }
                return PROBLEMA_ERROR_INVALID_UTF8;
            }
            unicode[j++] = ((utf8[i] & 0x1F) << 6) | (utf8[i + 1] & 0x3F);
            i += 2;
        }
        else if ((utf8[i] & 0xF0) == 0xE0)
        {
            /* 3바이트 UTF-8 시퀀스 (한글 포함) */
            if (i + 2 >= utf8_len || (utf8[i + 1] & 0xC0) != 0x80 || (utf8[i + 2] & 0xC0) != 0x80)
            {
                if (debug_mode)
                {
                    printf("[DEBUG] 유효하지 않은 3바이트 UTF-8 시퀀스: %02X %02X %02X\n",
                           utf8[i],
                           (i + 1 < utf8_len) ? utf8[i + 1] : 0,
                           (i + 2 < utf8_len) ? utf8[i + 2] : 0);
                }
                return PROBLEMA_ERROR_INVALID_UTF8;
            }
            unicode[j++] = ((utf8[i] & 0x0F) << 12) |
                           ((utf8[i + 1] & 0x3F) << 6) |
                           (utf8[i + 2] & 0x3F);
            i += 3;
        }
        else if ((utf8[i] & 0xF8) == 0xF0)
        {
            /* 4바이트 UTF-8 시퀀스 */
            if (i + 3 >= utf8_len ||
                (utf8[i + 1] & 0xC0) != 0x80 ||
                (utf8[i + 2] & 0xC0) != 0x80 ||
                (utf8[i + 3] & 0xC0) != 0x80)
            {
                if (debug_mode)
                {
                    printf("[DEBUG] 유효하지 않은 4바이트 UTF-8 시퀀스: %02X %02X %02X %02X\n",
                           utf8[i],
                           (i + 1 < utf8_len) ? utf8[i + 1] : 0,
                           (i + 2 < utf8_len) ? utf8[i + 2] : 0,
                           (i + 3 < utf8_len) ? utf8[i + 3] : 0);
                }
                return PROBLEMA_ERROR_INVALID_UTF8;
            }
            unicode[j++] = ((utf8[i] & 0x07) << 18) |
                           ((utf8[i + 1] & 0x3F) << 12) |
                           ((utf8[i + 2] & 0x3F) << 6) |
                           (utf8[i + 3] & 0x3F);
            i += 4;
        }
        else
        {
            /* 유효하지 않은 UTF-8 시퀀스 */
            if (debug_mode)
            {
                printf("[DEBUG] 유효하지 않은 UTF-8 시퀀스 시작 바이트: %02X\n", utf8[i]);
            }
            return PROBLEMA_ERROR_INVALID_UTF8;
        }
    }

    *unicode_len = j;

    if (i < utf8_len && j >= unicode_size)
    {
        return PROBLEMA_ERROR_BUFFER_TOO_SMALL;
    }

    if (debug_mode)
    {
        printf("[DEBUG] UTF-8 → 유니코드 변환: %zu 바이트 → %zu 문자\n", utf8_len, j);
    }

    return PROBLEMA_SUCCESS;
}

/**
 * @brief 유니코드 코드 포인트 배열을 UTF-8 문자열로 변환
 */
int unicode_to_utf8(const unicode_t *unicode, size_t unicode_len,
                    byte_t *utf8, size_t utf8_size, size_t *utf8_len)
{
    if (unicode == NULL || utf8 == NULL || utf8_len == NULL)
    {
        return PROBLEMA_ERROR_NULL_POINTER;
    }

    size_t i = 0, j = 0;

    for (i = 0; i < unicode_len; i++)
    {
        unicode_t code = unicode[i];

        if (code <= 0x7F)
        {
            /* ASCII 문자 (1바이트) */
            if (j + 1 > utf8_size)
            {
                if (debug_mode)
                {
                    printf("[DEBUG] 버퍼 크기 부족: ASCII 문자 U+%04X 인코딩 실패\n", code);
                }
                return PROBLEMA_ERROR_BUFFER_TOO_SMALL;
            }
            utf8[j++] = (byte_t)code;
        }
        else if (code <= 0x7FF)
        {
            /* 2바이트 UTF-8 시퀀스 */
            if (j + 2 > utf8_size)
            {
                if (debug_mode)
                {
                    printf("[DEBUG] 버퍼 크기 부족: 2바이트 문자 U+%04X 인코딩 실패\n", code);
                }
                return PROBLEMA_ERROR_BUFFER_TOO_SMALL;
            }
            utf8[j++] = (byte_t)(0xC0 | (code >> 6));
            utf8[j++] = (byte_t)(0x80 | (code & 0x3F));
        }
        else if (code <= 0xFFFF)
        {
            /* 3바이트 UTF-8 시퀀스 (한글 포함) */
            if (j + 3 > utf8_size)
            {
                if (debug_mode)
                {
                    printf("[DEBUG] 버퍼 크기 부족: 3바이트 문자 U+%04X 인코딩 실패\n", code);
                }
                return PROBLEMA_ERROR_BUFFER_TOO_SMALL;
            }
            utf8[j++] = (byte_t)(0xE0 | (code >> 12));
            utf8[j++] = (byte_t)(0x80 | ((code >> 6) & 0x3F));
            utf8[j++] = (byte_t)(0x80 | (code & 0x3F));
        }
        else if (code <= 0x10FFFF)
        {
            /* 4바이트 UTF-8 시퀀스 (이모지 등) */
            if (j + 4 > utf8_size)
            {
                if (debug_mode)
                {
                    printf("[DEBUG] 버퍼 크기 부족: 4바이트 문자 U+%04X 인코딩 실패\n", code);
                }
                return PROBLEMA_ERROR_BUFFER_TOO_SMALL;
            }
            utf8[j++] = (byte_t)(0xF0 | (code >> 18));
            utf8[j++] = (byte_t)(0x80 | ((code >> 12) & 0x3F));
            utf8[j++] = (byte_t)(0x80 | ((code >> 6) & 0x3F));
            utf8[j++] = (byte_t)(0x80 | (code & 0x3F));
        }
        else
        {
            /* 유효하지 않은 유니코드 코드 포인트 */
            return PROBLEMA_ERROR_INVALID_UTF8;
        }
    }

    *utf8_len = j;
    return PROBLEMA_SUCCESS;
}

/* 내부 함수 구현 */

/**
 * @brief 로터 초기화
 */
static void init_rotors(ProblemaContext *ctx)
{
    /* 키를 기반으로 로터 매핑 생성 */
    for (int r = 0; r < PROBLEMA_NUM_ROTORS; r++)
    {
        /* 로터 위치 초기화 */
        ctx->rotors[r].position = ctx->key[r % PROBLEMA_KEY_SIZE] % PROBLEMA_ROTOR_SIZE;

        /* 노치 위치 초기화 */
        ctx->rotors[r].num_notches = (ctx->key[(r + 1) % PROBLEMA_KEY_SIZE] % 7) + 1;
        for (int n = 0; n < ctx->rotors[r].num_notches; n++)
        {
            ctx->rotors[r].notch_positions[n] =
                (ctx->key[(r + n + 2) % PROBLEMA_KEY_SIZE] * 251) % PROBLEMA_ROTOR_SIZE;
        }

        /* 로터 매핑 초기화 (치환 테이블) */
        for (int i = 0; i < PROBLEMA_ROTOR_SIZE; i++)
        {
            ctx->rotors[r].mapping[i] = i;
        }

        /* Fisher-Yates 셔플 알고리즘으로 매핑 섞기 */
        for (int i = PROBLEMA_ROTOR_SIZE - 1; i > 0; i--)
        {
            int j = (ctx->key[(r + i) % PROBLEMA_KEY_SIZE] * i) % (i + 1);
            unicode_t temp = ctx->rotors[r].mapping[i];
            ctx->rotors[r].mapping[i] = ctx->rotors[r].mapping[j];
            ctx->rotors[r].mapping[j] = temp;
        }

        /* 역방향 로터 초기화 */
        for (int i = 0; i < PROBLEMA_ROTOR_SIZE; i++)
        {
            ctx->inverse_rotors[r].mapping[ctx->rotors[r].mapping[i]] = i;
        }
        ctx->inverse_rotors[r].position = ctx->rotors[r].position;
        ctx->inverse_rotors[r].num_notches = ctx->rotors[r].num_notches;
        for (int n = 0; n < ctx->rotors[r].num_notches; n++)
        {
            ctx->inverse_rotors[r].notch_positions[n] = ctx->rotors[r].notch_positions[n];
        }
    }

    if (debug_mode)
    {
        printf("[DEBUG] 로터 초기화 완료\n");
    }
}

/**
 * @brief 플러그보드 초기화
 */
static void init_plugboard(ProblemaContext *ctx)
{
    /* 초기 매핑은 항등 매핑 */
    for (int i = 0; i < PROBLEMA_ROTOR_SIZE; i++)
    {
        ctx->plugboard.mapping[i] = i;
    }

    /* 키를 기반으로 일부 문자 쌍 교환 */
    int num_swaps = (ctx->key[0] % 100) + 50;
    for (int i = 0; i < num_swaps; i++)
    {
        int a = (ctx->key[i % PROBLEMA_KEY_SIZE] * 251 + ctx->key[(i + 1) % PROBLEMA_KEY_SIZE]) % PROBLEMA_ROTOR_SIZE;
        int b = (ctx->key[(i + 2) % PROBLEMA_KEY_SIZE] * 251 + ctx->key[(i + 3) % PROBLEMA_KEY_SIZE]) % PROBLEMA_ROTOR_SIZE;

        unicode_t temp = ctx->plugboard.mapping[a];
        ctx->plugboard.mapping[a] = ctx->plugboard.mapping[b];
        ctx->plugboard.mapping[b] = temp;
    }

    if (debug_mode)
    {
        printf("[DEBUG] 플러그보드 초기화 완료\n");
    }
}

/**
 * @brief AES 컴포넌트 초기화
 */
static void init_aes_components(ProblemaContext *ctx)
{
    /* 간소화된 S-Box 초기화 (실제 AES S-Box 대신 키 기반 생성) */
    for (int i = 0; i < PROBLEMA_SBOX_SIZE; i++)
    {
        ctx->aes.sbox[i] = i;
    }

    /* 키를 기반으로 S-Box 섞기 */
    for (int i = PROBLEMA_SBOX_SIZE - 1; i > 0; i--)
    {
        int j = (ctx->key[i % PROBLEMA_KEY_SIZE] * i) % (i + 1);
        byte_t temp = ctx->aes.sbox[i];
        ctx->aes.sbox[i] = ctx->aes.sbox[j];
        ctx->aes.sbox[j] = temp;
    }

    /* 역 S-Box 생성 */
    for (int i = 0; i < PROBLEMA_SBOX_SIZE; i++)
    {
        ctx->aes.inv_sbox[ctx->aes.sbox[i]] = i;
    }

    /* 라운드 키 생성 (간소화된 키 스케줄링) */
    for (int round = 0; round <= PROBLEMA_NUM_ROUNDS; round++)
    {
        for (int i = 0; i < PROBLEMA_BLOCK_SIZE; i++)
        {
            ctx->aes.round_keys[round][i] = ctx->key[(i + round * 4) % PROBLEMA_KEY_SIZE];
        }
    }

    if (debug_mode)
    {
        printf("[DEBUG] AES 컴포넌트 초기화 완료\n");
    }
}

/**
 * @brief 로터 회전
 */
static void rotate_rotors(ProblemaContext *ctx)
{
    /* 첫 번째 로터는 항상 회전 */
    ctx->rotors[0].position = (ctx->rotors[0].position + 1) % PROBLEMA_ROTOR_SIZE;
    ctx->inverse_rotors[0].position = ctx->rotors[0].position;

    /* 나머지 로터는 이전 로터가 노치 위치에 있을 때 회전 */
    for (int r = 0; r < PROBLEMA_NUM_ROTORS - 1; r++)
    {
        bool at_notch = false;
        for (int n = 0; n < ctx->rotors[r].num_notches; n++)
        {
            if (ctx->rotors[r].position == ctx->rotors[r].notch_positions[n])
            {
                at_notch = true;
                break;
            }
        }

        if (at_notch)
        {
            ctx->rotors[r + 1].position = (ctx->rotors[r + 1].position + 1) % PROBLEMA_ROTOR_SIZE;
            ctx->inverse_rotors[r + 1].position = ctx->rotors[r + 1].position;
        }
        else
        {
            break;
        }
    }

    if (debug_mode)
    {
        printf("[DEBUG] 로터 회전 상태: ");
        for (int r = 0; r < PROBLEMA_NUM_ROTORS; r++)
        {
            printf("%d ", ctx->rotors[r].position);
        }
        printf("\n");
    }
}

/**
 * @brief 플러그보드 적용
 */
static unicode_t apply_plugboard(ProblemaContext *ctx, unicode_t input)
{
    if (input < PROBLEMA_ROTOR_SIZE)
    {
        return ctx->plugboard.mapping[input];
    }
    return input;
}

/**
 * @brief 순방향 로터 적용
 */
static unicode_t apply_rotors_forward(ProblemaContext *ctx, unicode_t input)
{
    if (input >= PROBLEMA_ROTOR_SIZE)
    {
        return input;
    }

    unicode_t output = input;

    for (int r = 0; r < PROBLEMA_NUM_ROTORS; r++)
    {
        int pos = ctx->rotors[r].position;
        output = ctx->rotors[r].mapping[(output + pos) % PROBLEMA_ROTOR_SIZE];
        output = (output + PROBLEMA_ROTOR_SIZE - pos) % PROBLEMA_ROTOR_SIZE;
    }

    return output;
}

/**
 * @brief 역방향 로터 적용
 */
static unicode_t apply_rotors_backward(ProblemaContext *ctx, unicode_t input)
{
    if (input >= PROBLEMA_ROTOR_SIZE)
    {
        return input;
    }

    unicode_t output = input;

    for (int r = PROBLEMA_NUM_ROTORS - 1; r >= 0; r--)
    {
        int pos = ctx->inverse_rotors[r].position;
        output = (output + pos) % PROBLEMA_ROTOR_SIZE;
        output = ctx->inverse_rotors[r].mapping[output];
        output = (output + PROBLEMA_ROTOR_SIZE - pos) % PROBLEMA_ROTOR_SIZE;
    }

    return output;
}

/**
 * @brief AES 변환 적용 (간소화된 버전)
 */
static void apply_aes_transformation(ProblemaContext *ctx, byte_t *block)
{
    byte_t temp[PROBLEMA_BLOCK_SIZE];

    if (debug_mode)
    {
        printf("[DEBUG] AES 변환 적용 시작 (암호화 모드)\n");
        debug_print_state("변환 전 블록", block, PROBLEMA_BLOCK_SIZE);
    }

    /* SubBytes */
    for (int i = 0; i < PROBLEMA_BLOCK_SIZE; i++)
    {
        temp[i] = ctx->aes.sbox[block[i]];
    }

    if (debug_mode)
    {
        debug_print_state("SubBytes 후", temp, PROBLEMA_BLOCK_SIZE);
    }

    /* ShiftRows (간소화된 버전) */
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            block[i * 4 + j] = temp[i * 4 + (j + i) % 4];
        }
    }

    if (debug_mode)
    {
        debug_print_state("ShiftRows 후", block, PROBLEMA_BLOCK_SIZE);
    }

    /* MixColumns (간소화된 버전) */
    memcpy(temp, block, PROBLEMA_BLOCK_SIZE);
    for (int i = 0; i < 4; i++)
    {
        byte_t a = temp[i * 4 + 0];
        byte_t b = temp[i * 4 + 1];
        byte_t c = temp[i * 4 + 2];
        byte_t d = temp[i * 4 + 3];

        block[i * 4 + 0] = (a ^ b) ^ 0;
        block[i * 4 + 1] = (b ^ c) ^ 0;
        block[i * 4 + 2] = (c ^ d) ^ 0;
        block[i * 4 + 3] = (d ^ a) ^ 0;
    }

    if (debug_mode)
    {
        debug_print_state("MixColumns 후", block, PROBLEMA_BLOCK_SIZE);
    }

    /* AddRoundKey */
    for (int i = 0; i < PROBLEMA_BLOCK_SIZE; i++)
    {
        block[i] ^= ctx->aes.round_keys[0][i];
    }

    if (debug_mode)
    {
        debug_print_state("AddRoundKey 후", block, PROBLEMA_BLOCK_SIZE);
        printf("[DEBUG] AES 변환 적용 완료\n");
    }
}

/**
 * @brief 역 AES 변환 적용 (간소화된 버전)
 */
static void apply_inverse_aes_transformation(ProblemaContext *ctx, byte_t *block)
{
    byte_t temp[PROBLEMA_BLOCK_SIZE];

    if (debug_mode)
    {
        printf("[DEBUG] 역 AES 변환 적용 시작 (복호화 모드)\n");
        debug_print_state("변환 전 블록", block, PROBLEMA_BLOCK_SIZE);
    }

    /* AddRoundKey (역순) */
    for (int i = 0; i < PROBLEMA_BLOCK_SIZE; i++)
    {
        block[i] ^= ctx->aes.round_keys[0][i];
    }

    if (debug_mode)
    {
        debug_print_state("AddRoundKey 후", block, PROBLEMA_BLOCK_SIZE);
    }

    /* InvMixColumns (간소화된 버전) */
    memcpy(temp, block, PROBLEMA_BLOCK_SIZE);

    for (int i = 0; i < 4; i++)
    {
        byte_t a = temp[i * 4 + 0];
        byte_t b = temp[i * 4 + 1];
        byte_t c = temp[i * 4 + 2];
        byte_t d = temp[i * 4 + 3];

        block[i * 4 + 0] = (d ^ a) ^ 0;
        block[i * 4 + 1] = (a ^ b) ^ 0;
        block[i * 4 + 2] = (b ^ c) ^ 0;
        block[i * 4 + 3] = (c ^ d) ^ 0;
    }

    if (debug_mode)
    {
        debug_print_state("InvMixColumns 후", block, PROBLEMA_BLOCK_SIZE);
    }

    /* InvShiftRows (간소화된 버전) */
    memcpy(temp, block, PROBLEMA_BLOCK_SIZE);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            block[i * 4 + (j + i) % 4] = temp[i * 4 + j];
        }
    }

    if (debug_mode)
    {
        debug_print_state("InvShiftRows 후", block, PROBLEMA_BLOCK_SIZE);
    }

    /* InvSubBytes */
    for (int i = 0; i < PROBLEMA_BLOCK_SIZE; i++)
    {
        block[i] = ctx->aes.inv_sbox[block[i]];
    }

    if (debug_mode)
    {
        debug_print_state("InvSubBytes 후", block, PROBLEMA_BLOCK_SIZE);
        printf("[DEBUG] 역 AES 변환 적용 완료\n");
    }
}

/**
 * @brief 피드백 상태 업데이트
 */
static void update_feedback(ProblemaContext *ctx, const byte_t *block)
{
    for (int i = 0; i < PROBLEMA_BLOCK_SIZE; i++)
    {
        ctx->feedback[i] = block[i];
    }
}

/**
 * @brief 디버그용 상태 출력
 */
static void debug_print_state(const char *label, const byte_t *data, size_t len)
{
    printf("[DEBUG] %s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

/**
 * @brief 디버그용 유니코드 출력
 */
static void debug_print_unicode(const char *label, unicode_t code)
{
    printf("[DEBUG] %s: U+%04X\n", label, code);
}