#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "problema.h"

#define MAX_INPUT_SIZE 4096
#define MAX_OUTPUT_SIZE 8192

void print_banner()
{
    printf("┌─────────────────────────────────────────────────────────────┐\n");
    printf("│                                                             │\n");
    printf("│  프로블레마(Problema) 암호화/복호화 프로그램                │\n");
    printf("│  애니그마와 AES를 결합한 한글/영어 교차지원 암호화 알고리즘 │\n");
    printf("│                                                             │\n");
    printf("└─────────────────────────────────────────────────────────────┘\n\n");
}

void print_usage()
{
    printf("사용법: problema [옵션] [입력]\n");
    printf("옵션:\n");
    printf("  -e, --encrypt    입력 텍스트를 암호화합니다\n");
    printf("  -d, --decrypt    입력 텍스트를 복호화합니다\n");
    printf("  -k, --key KEY    암호화/복호화에 사용할 키를 지정합니다 (필수)\n");
    printf("  -i, --input FILE 입력 파일을 지정합니다 (지정하지 않으면 표준 입력 사용)\n");
    printf("  -o, --output FILE 출력 파일을 지정합니다 (지정하지 않으면 표준 출력 사용)\n");
    printf("  -v, --verbose    상세 출력 모드를 활성화합니다\n");
    printf("  -h, --help       이 도움말을 표시합니다\n");
    printf("\n");
    printf("예시:\n");
    printf("  problema -e -k \"비밀키\" \"안녕하세요 Hello World\"\n");
    printf("  problema -d -k \"비밀키\" \"암호화된텍스트\"\n");
    printf("  echo \"안녕하세요 Hello World\" | problema -e -k \"비밀키\"\n");
    printf("  problema -e -k \"비밀키\" -i input.txt -o encrypted.txt\n");
}

// 문자열을 256비트(32바이트) 키로 변환
void derive_key_from_string(const char *key_str, byte_t *key)
{
    size_t key_len = strlen(key_str);

    // 키 초기화
    memset(key, 0, PROBLEMA_KEY_SIZE);

    // 간단한 키 유도 함수 (실제 구현에서는 더 강력한 KDF 사용 권장)
    for (size_t i = 0; i < PROBLEMA_KEY_SIZE; i++)
    {
        key[i] = key_str[i % key_len];

        // 추가 혼합
        for (size_t j = 0; j < key_len; j++)
        {
            key[i] ^= key_str[(i + j) % key_len];
            key[i] = ((key[i] << 3) | (key[i] >> 5)) & 0xFF; // 순환 시프트
        }
    }
}

// 암호화 과정 출력
void print_encryption_process(const byte_t *input, size_t input_len,
                              const byte_t *output, size_t output_len)
{
    printf("\n[암호화 과정]\n");

    printf("입력 텍스트 (UTF-8): ");
    for (size_t i = 0; i < input_len; i++)
    {
        printf("%02X ", input[i]);
    }
    printf("\n");

    // 유니코드 변환 과정 시뮬레이션
    printf("\n유니코드 변환 (UTF-8 → 코드 포인트):\n");
    size_t i = 0;
    while (i < input_len)
    {
        if ((input[i] & 0x80) == 0)
        {
            // ASCII 문자 (1바이트)
            printf("U+%04X (%c) → ", input[i], input[i]);
            i++;
        }
        else if ((input[i] & 0xE0) == 0xC0)
        {
            // 2바이트 UTF-8 시퀀스
            if (i + 1 < input_len)
            {
                int codepoint = ((input[i] & 0x1F) << 6) | (input[i + 1] & 0x3F);
                printf("U+%04X → ", codepoint);
                i += 2;
            }
            else
            {
                printf("(불완전한 UTF-8 시퀀스) → ");
                i++;
            }
        }
        else if ((input[i] & 0xF0) == 0xE0)
        {
            // 3바이트 UTF-8 시퀀스 (한글 포함)
            if (i + 2 < input_len)
            {
                int codepoint = ((input[i] & 0x0F) << 12) |
                                ((input[i + 1] & 0x3F) << 6) |
                                (input[i + 2] & 0x3F);
                printf("U+%04X → ", codepoint);
                i += 3;
            }
            else
            {
                printf("(불완전한 UTF-8 시퀀스) → ");
                i++;
            }
        }
        else if ((input[i] & 0xF8) == 0xF0)
        {
            // 4바이트 UTF-8 시퀀스
            if (i + 3 < input_len)
            {
                int codepoint = ((input[i] & 0x07) << 18) |
                                ((input[i + 1] & 0x3F) << 12) |
                                ((input[i + 2] & 0x3F) << 6) |
                                (input[i + 3] & 0x3F);
                printf("U+%04X → ", codepoint);
                i += 4;
            }
            else
            {
                printf("(불완전한 UTF-8 시퀀스) → ");
                i++;
            }
        }
        else
        {
            printf("(유효하지 않은 UTF-8 시퀀스) → ");
            i++;
        }
    }
    printf("\n");

    // 로터 및 플러그보드 처리 시뮬레이션
    printf("\n로터 및 플러그보드 처리:\n");
    printf("- 플러그보드 치환\n");
    printf("- 8개 로터 순방향 통과\n");
    printf("- 로터 회전\n");
    printf("- 8개 로터 역방향 통과\n");
    printf("- AES 변환 적용\n");

    printf("\n암호화된 출력 (UTF-8): ");
    for (size_t i = 0; i < output_len; i++)
    {
        printf("%02X ", output[i]);
    }
    printf("\n\n");
}

// 복호화 과정 출력
void print_decryption_process(const byte_t *input, size_t input_len,
                              const byte_t *output, size_t output_len)
{
    printf("\n[복호화 과정]\n");

    printf("암호화된 입력 (UTF-8): ");
    for (size_t i = 0; i < input_len; i++)
    {
        printf("%02X ", input[i]);
    }
    printf("\n");

    // 역 과정 시뮬레이션
    printf("\n역 AES 변환 적용\n");
    printf("8개 로터 역방향 통과\n");
    printf("로터 회전\n");
    printf("8개 로터 순방향 통과\n");
    printf("플러그보드 역치환\n");

    printf("\n복호화된 출력 (UTF-8): ");
    for (size_t i = 0; i < output_len; i++)
    {
        printf("%02X ", output[i]);
    }
    printf("\n");

    printf("\n복호화된 텍스트: %.*s\n\n", (int)output_len, output);
}

int main(int argc, char *argv[])
{
    bool encrypt_mode = true;
    bool verbose_mode = false;
    char *key_str = NULL;
    char *input_file = NULL;
    char *output_file = NULL;
    char *input_text = NULL;

    // 명령행 인수 파싱
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--encrypt") == 0)
        {
            encrypt_mode = true;
        }
        else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--decrypt") == 0)
        {
            encrypt_mode = false;
        }
        else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0)
        {
            if (i + 1 < argc)
            {
                key_str = argv[++i];
            }
            else
            {
                fprintf(stderr, "오류: 키가 지정되지 않았습니다.\n");
                print_usage();
                return 1;
            }
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0)
        {
            if (i + 1 < argc)
            {
                input_file = argv[++i];
            }
            else
            {
                fprintf(stderr, "오류: 입력 파일이 지정되지 않았습니다.\n");
                print_usage();
                return 1;
            }
        }
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0)
        {
            if (i + 1 < argc)
            {
                output_file = argv[++i];
            }
            else
            {
                fprintf(stderr, "오류: 출력 파일이 지정되지 않았습니다.\n");
                print_usage();
                return 1;
            }
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
        {
            verbose_mode = true;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_banner();
            print_usage();
            return 0;
        }
        else if (argv[i][0] == '-')
        {
            fprintf(stderr, "오류: 알 수 없는 옵션 '%s'\n", argv[i]);
            print_usage();
            return 1;
        }
        else
        {
            input_text = argv[i];
        }
    }

    // 키 검증
    if (key_str == NULL)
    {
        fprintf(stderr, "오류: 키가 지정되지 않았습니다. -k 옵션을 사용하세요.\n");
        print_usage();
        return 1;
    }

    print_banner();

    // 입력 데이터 준비
    byte_t input[MAX_INPUT_SIZE] = {0};
    size_t input_len = 0;

    if (input_file != NULL)
    {
        // 파일에서 입력 읽기
        FILE *fp = fopen(input_file, "rb");
        if (fp == NULL)
        {
            fprintf(stderr, "오류: 입력 파일 '%s'을(를) 열 수 없습니다.\n", input_file);
            return 1;
        }
        input_len = fread(input, 1, MAX_INPUT_SIZE - 1, fp);
        fclose(fp);
    }
    else if (input_text != NULL)
    {
        // 명령행 인수에서 입력 읽기
        input_len = strlen(input_text);
        if (input_len >= MAX_INPUT_SIZE)
        {
            fprintf(stderr, "오류: 입력 텍스트가 너무 깁니다.\n");
            return 1;
        }
        memcpy(input, input_text, input_len);
    }
    else
    {
        // 표준 입력에서 읽기
        fprintf(stderr, "입력 텍스트를 입력하세요 (최대 %d바이트):\n", MAX_INPUT_SIZE - 1);
        input_len = fread(input, 1, MAX_INPUT_SIZE - 1, stdin);

        // 줄바꿈 문자 제거
        if (input_len > 0 && input[input_len - 1] == '\n')
        {
            input_len--;
        }
    }

    // 키 유도
    byte_t key[PROBLEMA_KEY_SIZE];
    derive_key_from_string(key_str, key);

    // 프로블레마 컨텍스트 초기화
    ProblemaContext ctx;
    int result = problema_init(&ctx, key);
    if (result != PROBLEMA_SUCCESS)
    {
        fprintf(stderr, "오류: 프로블레마 컨텍스트 초기화 실패: %s\n",
                problema_error_string(result));
        return 1;
    }

    // 디버그 모드 설정
    if (verbose_mode)
    {
        problema_set_debug(true);
    }

    // 암호화 또는 복호화 수행
    byte_t output[MAX_OUTPUT_SIZE] = {0};
    size_t output_len = 0;

    if (encrypt_mode)
    {
        printf("암호화 모드\n");
        result = problema_encrypt(&ctx, input, input_len, output, MAX_OUTPUT_SIZE, &output_len);
        if (result != PROBLEMA_SUCCESS)
        {
            fprintf(stderr, "오류: 암호화 실패: %s\n", problema_error_string(result));
            problema_cleanup(&ctx);
            return 1;
        }

        if (verbose_mode)
        {
            print_encryption_process(input, input_len, output, output_len);
        }
    }
    else
    {
        printf("복호화 모드\n");
        result = problema_decrypt(&ctx, input, input_len, output, MAX_OUTPUT_SIZE, &output_len);
        if (result != PROBLEMA_SUCCESS)
        {
            fprintf(stderr, "오류: 복호화 실패: %s\n", problema_error_string(result));
            problema_cleanup(&ctx);
            return 1;
        }

        if (verbose_mode)
        {
            print_decryption_process(input, input_len, output, output_len);
        }
    }

    // 결과 출력
    if (output_file != NULL)
    {
        // 파일에 출력 쓰기
        FILE *fp = fopen(output_file, "wb");
        if (fp == NULL)
        {
            fprintf(stderr, "오류: 출력 파일 '%s'을(를) 열 수 없습니다.\n", output_file);
            problema_cleanup(&ctx);
            return 1;
        }
        fwrite(output, 1, output_len, fp);
        fclose(fp);
        printf("결과가 '%s' 파일에 저장되었습니다.\n", output_file);
    }
    else
    {
        // 표준 출력에 쓰기
        if (!verbose_mode)
        {
            if (encrypt_mode)
            {
                printf("암호화된 결과: ");
                // 암호화된 결과는 바이너리일 수 있으므로 16진수로 출력
                for (size_t i = 0; i < output_len; i++)
                {
                    printf("%02X", output[i]);
                }
                printf("\n");
            }
            else
            {
                printf("복호화된 결과: %.*s\n", (int)output_len, output);
            }
        }
    }

    // 정리
    problema_cleanup(&ctx);

    return 0;
}