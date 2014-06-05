/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <openssl/sha.h>

void usage()
{
	printf("shatest <filename> < 1 | 2 -- 1-openssl, 2-just read file>\n");
}
#define MAX_BUFFER_LEN (64*1024)
static void print_text(char *intro_message, unsigned char *text_addr,
						unsigned int size)
{
	unsigned int   i;

	printf("%s @ address = 0x%x\n", intro_message, (unsigned int)text_addr);
	for (i = 0;  i < size;  i++) {
		printf("%2x ", text_addr[i]);
		if ((i & 0xf) == 0xf)
			printf("\n");
	}
	printf("\n");
}

class Sha256HashMaker {
public:
    static const size_t DIGEST_LENGTH = SHA256_DIGEST_LENGTH;
    static const size_t HASH_SIZE = DIGEST_LENGTH*2+1;
    Sha256HashMaker() {
        SHA256_Init(&mSha256);
    }
    virtual ~Sha256HashMaker() { }
    virtual void AddToHash(const uint8_t *bytes, size_t byteCount) {
        SHA256_Update(&mSha256, bytes, byteCount);
    }
    virtual char* Finalize() {
        SHA256_Final(mHash, &mSha256);
        return ToString();
    }

protected:
	char output[HASH_SIZE];
    char* ToString() {
        static const char* HEX_TABLE[256] = {"00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"};

        for (int i=0; i < (int)DIGEST_LENGTH; i++) {
            ::memcpy(output + i * 2, HEX_TABLE[mHash[i]], 2);
        }
        output[HASH_SIZE - 1] = '\0';
        // Size to String does NOT include the null at the end
        return output;
    }

protected:
    unsigned char mHash[DIGEST_LENGTH];

private:
    SHA256_CTX mSha256;
};

static uint64_t microseconds()
{
    struct timespec tts;
    clock_gettime(CLOCK_MONOTONIC,&tts);
    uint64_t t = tts.tv_sec;
    return t*1000000 + tts.tv_nsec/1000;
}


int main(int argc, char** argv)
{
    FILE *inputFile = NULL;
    static uint8_t inBuffer[MAX_BUFFER_LEN];
    size_t inBytes,totalBytes;
    int fd,testtype;
    uint64_t starttime,endtime;
    if (argc != 3)
    {
		usage();
        return 0;
	}
    testtype = atoi(argv[2]);

    inputFile = fopen(argv[1],"rb");
    if (inputFile == NULL)
    {
        printf("Could not open input file %s\n",argv[1]);
        return -1;
    }

    if (testtype == 1)
    {
        Sha256HashMaker shamaker;
        starttime = microseconds();
        while ((inBytes = fread(inBuffer,1,MAX_BUFFER_LEN,inputFile)) > 0)
        {
            shamaker.AddToHash(inBuffer,inBytes);
        }
        char* result = shamaker.Finalize();
        endtime = microseconds();
        printf("OpenSSL SHA256 = %s\n",result);
        printf("OpenSSL SHA256 took %llu ms\n", (endtime-starttime)/1000);
    }
    else
    {
        starttime = microseconds();
        while ((inBytes = fread(inBuffer,1,MAX_BUFFER_LEN,inputFile)) > 0)
        {
        }
        endtime = microseconds();
        printf("Reading file took %llu ms\n", (endtime-starttime)/1000);
    }

    fclose(inputFile);

    return 0; 
}
