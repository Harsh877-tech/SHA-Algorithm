#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstdint>

// Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32
// Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
// Note 3: The compression function uses 8 working variables, a through h
// Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
//     and when parsing message block data from bytes to words, for example,
//     the first word of the input message "abc" after padding is 0x61626380

// Initialize hash values:
// (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
uint32_t h0 = 0x6a09e667;
uint32_t h1 = 0xbb67ae85;
uint32_t h2 = 0x3c6ef372;
uint32_t h3 = 0xa54ff53a;
uint32_t h4 = 0x510e527f;
uint32_t h5 = 0x9b05688c;
uint32_t h6 = 0x1f83d9ab;
uint32_t h7 = 0x5be0cd19;

// Initialize array of round constants:
// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTRIGHT(word,bits) (((word) >> (bits)) | ((word) << (32-(bits))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

std::string sha256(const std::string& input) {
    std::vector<uint8_t> message(input.begin(), input.end());
    uint64_t original_bit_length = message.size() * 8;

    // Pre-processing (Padding):
    message.push_back(0x80);
    while ((message.size() * 8 + 64) % 512 != 0) {
        message.push_back(0x00);
    }
    for (int i = 0; i < 8; i++) {
        message.push_back((original_bit_length >> (56 - i * 8)) & 0xFF);
    }

    // Process the message in successive 512-bit chunks:
    for (size_t i = 0; i < message.size(); i += 64) {
        uint32_t w[64];

        // Create a 64-entry message schedule array w[0..63] of 32-bit words
        for (int j = 0; j < 16; j++) {
            w[j] = (message[i + j * 4] << 24) | (message[i + j * 4 + 1] << 16) | (message[i + j * 4 + 2] << 8) | message[i + j * 4 + 3];
        }

        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for (int j = 16; j < 64; j++) {
            w[j] = SIG1(w[j - 2]) + w[j - 7] + SIG0(w[j - 15]) + w[j - 16];
        }

        // Initialize working variables to current hash value:
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

        // Compression function main loop:
        for (int j = 0; j < 64; j++) {
            uint32_t S1 = EP1(e);
            uint32_t ch = CH(e, f, g);
            uint32_t temp1 = h + S1 + ch + k[j] + w[j];
            uint32_t S0 = EP0(a);
            uint32_t maj = MAJ(a, b, c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Add the compressed chunk to the current hash value:
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
    }

    // Produce the final hash value (big-endian):
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(8) << h0 << std::setw(8) << h1 << std::setw(8) << h2 << std::setw(8) << h3
        << std::setw(8) << h4 << std::setw(8) << h5 << std::setw(8) << h6 << std::setw(8) << h7;
    return ss.str();
}

int main() {
    std::string filename = "C:\\Users\\reddy\\OneDrive\\Documents\\sha256_book_of_mark.txt";
    std::ifstream file(filename, std::ios::binary);
    std::string bookOfMark;

    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return 1;
    }

    bookOfMark = std::string((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    file.close();

    if (bookOfMark.empty()) {
        std::cerr << "File is empty or could not be read." << std::endl;
        return 1;
    }

    std::string hash = sha256(bookOfMark);
    std::cout << "SHA-256 hash of the Book of Mark: " << hash << std::endl;

    return 0;
}
