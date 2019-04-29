#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <iostream>
#include <sys/time.h>

#define MERKLE_DEPTH	16
#define INPUT_SIZE	64

void sha256_run (unsigned char *input_buffer, int input_length, unsigned char *output_buffer) {
    //unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input_buffer, input_length);
    SHA256_Final(output_buffer, &ctx);
}

int main() {

    unsigned char *buffer = new unsigned char[INPUT_SIZE];
    if (RAND_bytes(buffer, INPUT_SIZE) != 1 ) {
	std::cerr << "Could not produce random bytes: " << INPUT_SIZE << std::endl;
	return false;
    } 

    struct timeval start, end;

    unsigned char *input = buffer;	// Initialization Value
    unsigned char digest[SHA256_DIGEST_LENGTH];


    gettimeofday(&start, NULL);
    for (int i = 0; i < MERKLE_DEPTH ; i++) {
	sha256_run(buffer, INPUT_SIZE, digest);
	input = digest;	

        std::cout << "Done!! : " << i << std::endl;
    }
    gettimeofday(&end, NULL);
    std::cout << "take time : " << (end.tv_sec - start.tv_sec) << " second " << (end.tv_usec - start.tv_usec) <<  " microseconds" << std::endl;

    delete[] buffer;

    return 0;
}
