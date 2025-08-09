#include <windows.h>
#include <wmmintrin.h>    
#include <bcrypt.h>         // BCryptGenRandom 
#include <stdio.h>


//\
#define C_CODE



#ifdef C_CODE

// C is for the losers

static void Aes256CBCKeyExpansion(const unsigned char* pAesKey, __m128i* pKeySchedule)
{
    __m128i xmmTemp1, xmmTemp2, xmmTemp3;

    // Load master key
    xmmTemp1 = _mm_loadu_si128((const __m128i*)pAesKey);
    xmmTemp2 = _mm_loadu_si128((const __m128i*)(pAesKey + 16));
    pKeySchedule[0] = xmmTemp1;
    pKeySchedule[1] = xmmTemp2;

    // Round 1
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x01);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[2] = xmmTemp1;

    // Round 1 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[3] = xmmTemp2;

    // Round 2
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x02);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[4] = xmmTemp1;

    // Round 2 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[5] = xmmTemp2;

    // Round 3
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x04);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[6] = xmmTemp1;

    // Round 3 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[7] = xmmTemp2;

    // Round 4
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x08);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[8] = xmmTemp1;

    // Round 4 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[9] = xmmTemp2;

    // Round 5
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x10);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[10] = xmmTemp1;

    // Round 5 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[11] = xmmTemp2;

    // Round 6
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x20);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[12] = xmmTemp1;

    // Round 6 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[13] = xmmTemp2;

    // Round 7
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x40);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[14] = xmmTemp1;
}

void Aes256CBCEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbEncrypted)
{
    if (!pbEncrypted) return;

    *pbEncrypted = FALSE;

    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;
    if (uPlainTextSize % 16 != 0) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);

    for (unsigned __int64 uIndex = 0; uIndex < uPlainTextSize; uIndex += 16)
    {
        __m128i xmmBlock = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        xmmBlock = _mm_xor_si128(xmmBlock, xmmChain);
        xmmBlock = _mm_xor_si128(xmmBlock, xmmKeySchedule[0]);

        for (int iRound = 1; iRound < 14; iRound++)
            xmmBlock = _mm_aesenc_si128(xmmBlock, xmmKeySchedule[iRound]);

        xmmBlock = _mm_aesenclast_si128(xmmBlock, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmBlock);
        xmmChain = xmmBlock;
    }

    *pbEncrypted = TRUE;
}

void Aes256CBCDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbDecrypted)
{

    if (!pbDecrypted) return;
    *pbDecrypted = FALSE;

    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;
    if (uCipherTextSize % 16 != 0) return;

    __m128i xmmEncKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmEncKeySchedule);

    __m128i xmmDecKeySchedule[15];
    xmmDecKeySchedule[0] = xmmEncKeySchedule[14];
    for (int i = 1; i < 14; i++)
        xmmDecKeySchedule[i] = _mm_aesimc_si128(xmmEncKeySchedule[14 - i]);
    xmmDecKeySchedule[14] = xmmEncKeySchedule[0];

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);


    for (unsigned __int64 uIndex = 0; uIndex < uCipherTextSize; uIndex += 16)
    {
        __m128i xmmCipherBlock = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmTemp = xmmCipherBlock;

        __m128i xmmBlock = _mm_xor_si128(xmmCipherBlock, xmmDecKeySchedule[0]);

        for (int iRound = 1; iRound < 14; iRound++)
            xmmBlock = _mm_aesdec_si128(xmmBlock, xmmDecKeySchedule[iRound]);

        xmmBlock = _mm_aesdeclast_si128(xmmBlock, xmmDecKeySchedule[14]);
        xmmBlock = _mm_xor_si128(xmmBlock, xmmChain);

        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmBlock);

        xmmChain = xmmTemp;
    }

    *pbDecrypted = TRUE;
}

#else

extern VOID Aes256CBCKeyExpansion(CONST UCHAR* pAesKey, __m128i* pKeySchedule);
extern VOID Aes256CBCEncrypt(CONST UCHAR* pPlainText, ULONGLONG uPlainTextSize, UCHAR* pCipherText, UCHAR* pAesKey, UCHAR* pAesIv, PBOOLEAN pbEncrypted);
extern VOID Aes256CBCDecrypt(CONST UCHAR* pCipherText, ULONGLONG uCipherTextSize, UCHAR* pPlainText, UCHAR* pAesKey, UCHAR* pAesIv, PBOOLEAN pbDecrypted);


#endif // C_CODE



VOID HexDump(IN OPTIONAL LPCSTR lpDescription, IN PVOID pAddress, IN DWORD dwLength) {

    INT         i           = 0;
    UCHAR       pBuff[17]   = { 0 };
    UCHAR*      pPntr       = (UCHAR*)pAddress;

    if (lpDescription != NULL)
        printf("%s [%d]:\n", lpDescription, dwLength);

    if (dwLength == 0 || dwLength < 0)
        return;

    for (i = 0; i < dwLength; i++) {

        if ((i % 0x10) == 0x00) {

            if (i != 0)
                printf("  %s\n", pBuff);

            printf("  %04x ", i);
        }

        printf(" %02x", pPntr[i]);

        if ((pPntr[i] < 0x20) || (pPntr[i] > 0x7E))
            pBuff[i % 0x10] = '.';
        else
            pBuff[i % 0x10] = pPntr[i];

        pBuff[(i % 0x10) + 1] = '\0';
    }

    while ((i % 0x10) != 0) {
        printf("   ");
        i++;
    }

    printf("  %s\n", pBuff);
}





int main(void)
{
    const UCHAR         kPlain[]                        = "@NUL0x4c @NUL0x4c @NUL0x4c NULL";    // 32 bytes 
    const ULONGLONG     uPlainSize                      = sizeof(kPlain);                       
    UCHAR               bAesKey[32]                     = { 0 };
    UCHAR               bAesIv[16]                      = { 0 };
    UCHAR               bCipherText[sizeof(kPlain)]     = { 0 }; 
	UCHAR               bPlainText[sizeof(kPlain)]      = { 0 }; 
    BOOLEAN             bEncrypted                      = FALSE, 
                        bDecrypted                      = FALSE;


    (void)BCryptGenRandom(NULL, bAesKey, sizeof(bAesKey), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    (void)BCryptGenRandom(NULL, bAesIv, sizeof(bAesIv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);


    HexDump("Aes Key", bAesKey, sizeof(bAesKey));
    HexDump("Aes Iv", bAesIv, sizeof(bAesIv));
    printf("\n\n");


    Aes256CBCEncrypt(kPlain, uPlainSize, bCipherText, bAesKey, bAesIv, &bEncrypted);

    if (!bEncrypted)
    {
		printf("[!] Encryption Failed\n");
		return -1;
    }

    HexDump("CipherText", bCipherText, uPlainSize);
    printf("\n\n");


    Aes256CBCDecrypt(bCipherText, uPlainSize, bPlainText, bAesKey, bAesIv, &bDecrypted);

    if (!bDecrypted)
    {
        printf("[!] Decryption Failed\n");
        return -1;
    }

    HexDump("PlainText", bPlainText, uPlainSize);
    printf("\n\n");


    if (memcmp(kPlain, bPlainText, uPlainSize) == 0)
        printf("[+] Success: Plaintext Restored \n");
    else
        printf("[!] Mismatch: Something's Wrong!\n");

    return 0;
}
