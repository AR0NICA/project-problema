/**
 * @file problema.h
 * @brief 프로블레마(Problema) 암호화 알고리즘 헤더 파일
 *
 * 이 파일은 프로블레마 암호화 알고리즘의 주요 구조체와 함수 선언을 포함합니다.
 * 프로블레마는 애니그마 알고리즘을 개선하고 AES 암호화 알고리즘과 결합한
 * 한글/영어 교차지원이 가능한 새로운 암호화 알고리즘입니다.
 * 해당 알고리즘은 보안전공 학부생의 실습 목적으로 제작되었으며, 실사용을 권장하지 않습니다.
 */

#ifndef PROBLEMA_H
#define PROBLEMA_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/* 상수 정의 */
#define PROBLEMA_KEY_SIZE 32      // 256비트 키
#define PROBLEMA_BLOCK_SIZE 16    // 128비트 블록
#define PROBLEMA_NUM_ROTORS 8     // 로터 개수
#define PROBLEMA_ROTOR_SIZE 65536 // 유니코드 기본 다국어 평면 크기
#define PROBLEMA_NUM_ROUNDS 14    // 암호화 라운드 수
#define PROBLEMA_SBOX_SIZE 256    // S-Box 크기

/* 오류 코드 */
#define PROBLEMA_SUCCESS 0
#define PROBLEMA_ERROR_NULL_POINTER -1
#define PROBLEMA_ERROR_INVALID_KEY -2
#define PROBLEMA_ERROR_NOT_INITIALIZED -3
#define PROBLEMA_ERROR_BUFFER_TOO_SMALL -4
#define PROBLEMA_ERROR_INVALID_UTF8 -5

/* 타입 정의 */
typedef uint8_t byte_t;
typedef uint32_t unicode_t;

/**
 * @brief 프로블레마 로터 구조체
 */
typedef struct
{
    unicode_t mapping[PROBLEMA_ROTOR_SIZE]; // 로터 매핑 테이블
    int position;                           // 현재 로터 위치
    int notch_positions[8];                 // 노치 위치 (다음 로터 회전 트리거)
    int num_notches;                        // 노치 개수
} ProblemaRotor;

/**
 * @brief 프로블레마 플러그보드 구조체
 */
typedef struct
{
    unicode_t mapping[PROBLEMA_ROTOR_SIZE]; // 플러그보드 매핑 테이블
} ProblemaPlugboard;

/**
 * @brief AES 컴포넌트 구조체
 */
typedef struct
{
    byte_t sbox[PROBLEMA_SBOX_SIZE];                                 // S-Box
    byte_t inv_sbox[PROBLEMA_SBOX_SIZE];                             // 역 S-Box
    byte_t round_keys[PROBLEMA_NUM_ROUNDS + 1][PROBLEMA_BLOCK_SIZE]; // 라운드 키
} ProblemaAES;

/**
 * @brief 프로블레마 컨텍스트 구조체
 */
typedef struct
{
    ProblemaRotor rotors[PROBLEMA_NUM_ROTORS];         // 로터 배열
    ProblemaRotor inverse_rotors[PROBLEMA_NUM_ROTORS]; // 역방향 로터 배열
    ProblemaPlugboard plugboard;                       // 플러그보드
    ProblemaAES aes;                                   // AES 컴포넌트
    byte_t key[PROBLEMA_KEY_SIZE];                     // 마스터 키
    byte_t feedback[PROBLEMA_BLOCK_SIZE];              // 피드백 상태
    byte_t initial_feedback[PROBLEMA_BLOCK_SIZE];      // 초기 피드백 상태 (복호화용)
    bool encrypt_mode;                                 // 암호화 모드 플래그
    bool initialized;                                  // 초기화 상태
} ProblemaContext;

/* 함수 선언 */

/**
 * @brief 프로블레마 컨텍스트 초기화
 *
 * @param ctx 초기화할 프로블레마 컨텍스트
 * @param key 256비트(32바이트) 키
 * @return int 성공 시 0, 실패 시 오류 코드
 */
int problema_init(ProblemaContext *ctx, const byte_t *key);

/**
 * @brief 프로블레마 컨텍스트 해제
 *
 * @param ctx 해제할 프로블레마 컨텍스트
 */
void problema_cleanup(ProblemaContext *ctx);

/**
 * @brief 단일 유니코드 문자 암호화
 *
 * @param ctx 프로블레마 컨텍스트
 * @param input 입력 유니코드 문자
 * @return unicode_t 암호화된 유니코드 문자
 */
unicode_t problema_encrypt_char(ProblemaContext *ctx, unicode_t input);

/**
 * @brief 단일 유니코드 문자 복호화
 *
 * @param ctx 프로블레마 컨텍스트
 * @param input 암호화된 유니코드 문자
 * @return unicode_t 복호화된 유니코드 문자
 */
unicode_t problema_decrypt_char(ProblemaContext *ctx, unicode_t input);

/**
 * @brief 블록 암호화
 *
 * @param ctx 프로블레마 컨텍스트
 * @param input 입력 블록 (16바이트)
 * @param output 출력 블록 (16바이트)
 */
void problema_encrypt_block(ProblemaContext *ctx, const byte_t *input, byte_t *output);

/**
 * @brief 블록 복호화
 *
 * @param ctx 프로블레마 컨텍스트
 * @param input 암호화된 블록 (16바이트)
 * @param output 복호화된 블록 (16바이트)
 */
void problema_decrypt_block(ProblemaContext *ctx, const byte_t *input, byte_t *output);

/**
 * @brief UTF-8 문자열 암호화
 *
 * @param ctx 프로블레마 컨텍스트
 * @param input 입력 UTF-8 문자열
 * @param input_len 입력 문자열 길이 (바이트)
 * @param output 출력 버퍼
 * @param output_size 출력 버퍼 크기
 * @param output_len 실제 출력 길이 (바이트)
 * @return int 성공 시 0, 실패 시 오류 코드
 */
int problema_encrypt(ProblemaContext *ctx, const byte_t *input, size_t input_len,
                     byte_t *output, size_t output_size, size_t *output_len);

/**
 * @brief UTF-8 문자열 복호화
 *
 * @param ctx 프로블레마 컨텍스트
 * @param input 암호화된 데이터
 * @param input_len 입력 데이터 길이 (바이트)
 * @param output 출력 버퍼
 * @param output_size 출력 버퍼 크기
 * @param output_len 실제 출력 길이 (바이트)
 * @return int 성공 시 0, 실패 시 오류 코드
 */
int problema_decrypt(ProblemaContext *ctx, const byte_t *input, size_t input_len,
                     byte_t *output, size_t output_size, size_t *output_len);

/**
 * @brief 암호화 과정 디버그 정보 출력 활성화/비활성화
 *
 * @param enable true: 활성화, false: 비활성화
 */
void problema_set_debug(bool enable);

/**
 * @brief 오류 코드에 대한 설명 문자열 반환
 *
 * @param error_code 오류 코드
 * @return const char* 오류 설명 문자열
 */
const char *problema_error_string(int error_code);

/* 유틸리티 함수 */

/**
 * @brief UTF-8 문자열을 유니코드 코드 포인트 배열로 변환
 *
 * @param utf8 UTF-8 문자열
 * @param utf8_len UTF-8 문자열 길이 (바이트)
 * @param unicode 유니코드 코드 포인트 배열
 * @param unicode_size 배열 크기
 * @param unicode_len 변환된 유니코드 문자 개수
 * @return int 성공 시 0, 실패 시 오류 코드
 */
int utf8_to_unicode(const byte_t *utf8, size_t utf8_len,
                    unicode_t *unicode, size_t unicode_size, size_t *unicode_len);

/**
 * @brief 유니코드 코드 포인트 배열을 UTF-8 문자열로 변환
 *
 * @param unicode 유니코드 코드 포인트 배열
 * @param unicode_len 유니코드 문자 개수
 * @param utf8 UTF-8 문자열 버퍼
 * @param utf8_size 버퍼 크기
 * @param utf8_len 변환된 UTF-8 문자열 길이 (바이트)
 * @return int 성공 시 0, 실패 시 오류 코드
 */
int unicode_to_utf8(const unicode_t *unicode, size_t unicode_len,
                    byte_t *utf8, size_t utf8_size, size_t *utf8_len);

#endif /* PROBLEMA_H */