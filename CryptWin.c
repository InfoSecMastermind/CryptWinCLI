#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define AES_KEY_SIZE 256
#define BUFFER_SIZE 1024

// Function prototypes
bool encryptFile(char* sourcePath, char* password, char* destPath);
bool decryptFile(char* sourcePath, char* password, char* destPath);

int main() {
    char sourcePath[MAX_PATH];
    char password[100];
    char destPath[MAX_PATH];
    int choice;

    printf("Welcome to CryptWin\n");
    printf(" \n");

// Ask the user what they want to do
	printf("So, what do you wanna do today?\n");
	printf(" \n");
	printf("1. Encrypt a file\n");
	printf("2. Decrypt a file\n");
	printf(" \n");
	printf("Enter your choice (1 or 2): "); // Prompt the user to enter their choice
	scanf("%d", &choice);

    if (choice == 1) {
        printf("Alrighty then, let's encrypt!\n");
        printf(" \n");
        printf("Just tell me the file path you want to encrypt (Paste it) :  ");
        scanf("%s", sourcePath);
        printf("And give me a password to keep it safe: ");
        scanf("%s", password);
        printf("Where should I save the encrypted file? (You can press 's' for the same path): ");
        scanf("%s", destPath);
        
        if (encryptFile(sourcePath, password, destPath)) {
            printf("File encrypted successfully!\n");
        } else {
            printf("Failed to encrypt file.\n");
        }
    } else if (choice == 2) {
        printf("Alright, let's decrypt!\n");
        printf(" \n");
        printf("Just tell me the file path you want to decrypt (Paste it) :  ");
        scanf("%s", sourcePath);
        printf("And what's the secret password?: ");
        scanf("%s", password);
        printf("Where should I save the decrypted file? (You can press 's' for the same path): ");
        scanf("%s", destPath);

        if (decryptFile(sourcePath, password, destPath)) {
            printf("File decrypted successfully!\n");
        } else {
            printf("Failed to decrypt file.\n");
        }
    } else {
        printf("Invalid choice.\n");
    }

    return 0;
}
// Function to encrypt a file

bool encryptFile(char* sourcePath, char* password, char* destPath) {
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestFile = INVALID_HANDLE_VALUE;
    BYTE pbBuffer[BUFFER_SIZE] = {0};
    DWORD dwCount = 0;
    DWORD dwBlockLen = 0;
    DWORD dwBufferLen = 0;
    BOOL bFinal = FALSE;

    // First, I need to get hold of a cryptographic service provider (CSP)
    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        dwStatus = GetLastError();
        printf("Error %d: CryptAcquireContext failed\n", dwStatus);
        return false;
    }

    // Now, I'll create a hash of the password to derive a symmetric key
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hKey)) {
        dwStatus = GetLastError();
        printf("Error %d: CryptCreateHash failed\n", dwStatus);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }
    
    // I put the password into the hash
    if (!CryptHashData(hKey, (BYTE*)password, strlen(password), 0)) {
        dwStatus = GetLastError();
        printf("Error %d: CryptHashData failed\n", dwStatus);
        CryptDestroyHash(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }


    // Now, I derive the AES-256 key from the hash
    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hKey, 0, &hKey)) {
        dwStatus = GetLastError();
        printf("Error %d: CryptDeriveKey failed\n", dwStatus);
        CryptDestroyHash(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Open source file
    hSourceFile = CreateFile(sourcePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSourceFile == INVALID_HANDLE_VALUE) {
        dwStatus = GetLastError();
        printf("Error %d: Unable to open source file\n", dwStatus);
        CryptDestroyHash(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Create destination file
    hDestFile = CreateFile(destPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDestFile == INVALID_HANDLE_VALUE) {
        dwStatus = GetLastError();
        printf("Error %d: Unable to create destination file\n", dwStatus);
        CloseHandle(hSourceFile);
        CryptDestroyHash(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Encrypt data from source file and write to destination file
    while (bResult = ReadFile(hSourceFile, pbBuffer, BUFFER_SIZE, &dwCount, NULL)) {
        if (dwCount == 0) {
            break;
        }
        if (!CryptEncrypt(hKey, NULL, bFinal, 0, pbBuffer, &dwCount, BUFFER_SIZE)) {
            dwStatus = GetLastError();
            printf("Error %d: CryptEncrypt failed\n", dwStatus);
            CloseHandle(hSourceFile);
            CloseHandle(hDestFile);
            CryptDestroyHash(hKey);
            CryptReleaseContext(hCryptProv, 0);
            return false;
        }
        if (!WriteFile(hDestFile, pbBuffer, dwCount, &dwCount, NULL)) {
            dwStatus = GetLastError();
            printf("Error %d: Unable to write to destination file\n", dwStatus);
            CloseHandle(hSourceFile);
            CloseHandle(hDestFile);
            CryptDestroyHash(hKey);
            CryptReleaseContext(hCryptProv, 0);
            return false;
        }
    }

    // Clean up resources
    CloseHandle(hSourceFile);
    CloseHandle(hDestFile);
    CryptDestroyHash(hKey);
    CryptReleaseContext(hCryptProv, 0);

    return true;
}


bool decryptFile(char* sourcePath, char* password, char* destPath) {
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestFile = INVALID_HANDLE_VALUE;
    BYTE pbBuffer[BUFFER_SIZE] = {0};
    DWORD dwCount = 0;
    DWORD dwBlockLen = 0;
    DWORD dwBufferLen = 0;
    BOOL bFinal = FALSE;

    // Acquire a handle to the default cryptographic service provider (CSP)
    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        dwStatus = GetLastError();
        printf("Error %d: CryptAcquireContext failed\n", dwStatus);
        return false;
    }

    // Derive a symmetric key from a password
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hKey)) {
        dwStatus = GetLastError();
        printf("Error %d: CryptCreateHash failed\n", dwStatus);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    if (!CryptHashData(hKey, (BYTE*)password, strlen(password), 0)) {
        dwStatus = GetLastError();
        printf("Error %d: CryptHashData failed\n", dwStatus);
        CryptDestroyHash(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hKey, 0, &hKey)) {
        dwStatus = GetLastError();
        printf("Error %d: CryptDeriveKey failed\n", dwStatus);
        CryptDestroyHash(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Open source file
    hSourceFile = CreateFile(sourcePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSourceFile == INVALID_HANDLE_VALUE) {
        dwStatus = GetLastError();
        printf("Error %d: Unable to open source file\n", dwStatus);
        CryptDestroyHash(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Create destination file
    hDestFile = CreateFile(destPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDestFile == INVALID_HANDLE_VALUE) {
        dwStatus = GetLastError();
        printf("Error %d: Unable to create destination file\n", dwStatus);
        CloseHandle(hSourceFile);
        CryptDestroyHash(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Decrypt data from source file and write to destination file
    while (bResult = ReadFile(hSourceFile, pbBuffer, BUFFER_SIZE, &dwCount, NULL)) {
        if (dwCount == 0) {
            break;
        }
        if (!CryptDecrypt(hKey, NULL, bFinal, 0, pbBuffer, &dwCount)) {
            dwStatus = GetLastError();
            printf("Error %d: CryptDecrypt failed\n", dwStatus);
            CloseHandle(hSourceFile);
            CloseHandle(hDestFile);
            CryptDestroyHash(hKey);
            CryptReleaseContext(hCryptProv, 0);
            return false;
        }
        if (!WriteFile(hDestFile, pbBuffer, dwCount, &dwCount, NULL)) {
            dwStatus = GetLastError();
            printf("Error %d: Unable to write to destination file\n", dwStatus);
            CloseHandle(hSourceFile);
            CloseHandle(hDestFile);
            CryptDestroyHash(hKey);
            CryptReleaseContext(hCryptProv, 0);
            return false;
        }
    }

    // Clean up resources
    CloseHandle(hSourceFile);
    CloseHandle(hDestFile);
    CryptDestroyHash(hKey);
    CryptReleaseContext(hCryptProv, 0);

    return true;
}
