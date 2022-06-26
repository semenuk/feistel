#include <unistd.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <libgen.h>

constexpr int ROUNDS = 8;

uint32_t crypt_func(uint32_t x, uint32_t k)
{
    return (x << 6) ^ (x >> 26) ^ k;
}

void create_key(const char * source_key, uint32_t * key)
{
	 for (int i = 0; i < 8; i = i + 1) {
		 key[i] = (source_key[i] << 24 | source_key[i+1] << 16 | source_key[i+2] << 8 | source_key[i+3]);
	 }
}

uint64_t feistel(uint64_t block,
                 uint32_t * key,
                 size_t rounds,
                 bool decrypt)
{
	uint32_t l, r;
    l = (block >> 32) & 0xffffffff;
    r = (block >> 0 ) & 0xffffffff;

    for (size_t i = 0; i < rounds; ++i) {
        uint32_t t, k;
        if (not decrypt) {
            k = key[i];
        } else {
            k = key[rounds - 1 - i];
        }
        t = r;
        r = l;
        l = t ^ crypt_func(l, k);
    }

    return (uint64_t(r) << 32) | l;
}


void draw_bar(int length, int max)
{
	std::cout << "\r[";
	int i;
	for (int i = 0; i < length; ++i)
		std::cout << "#";
	for (; i < max; ++i)
		std::cout << " ";
	std::cout << "]";
}

void file_crypt(const char * input_filename,
                const char * output_filename,
				const char * source_key,
                bool decrypt)
{
    std::ifstream in_file;
    std::ofstream out_file;

    in_file.open(input_filename, std::ios::binary | std::ios::ate);

    if (not in_file.good())
        throw std::runtime_error(
            std::string("Не могу открыть входной файл ") +
            std::string(input_filename)
        );

    size_t file_size;

    if (not decrypt) {
        file_size = in_file.tellg();
        in_file.seekg(0);
    } else {
        in_file.seekg(0);
        in_file.read(reinterpret_cast<char*>(&file_size), sizeof(file_size));
    }

    size_t block_count = file_size / sizeof(uint64_t);
    if (file_size % sizeof(uint64_t) != 0) block_count++;

    out_file.open(output_filename, std::ios::binary);
    if (not decrypt) {
        out_file.write(reinterpret_cast<char*>(&file_size), sizeof(file_size));
    }

    int bar_max = 32;
    int bar_current = -1;

    uint32_t key[8];
	create_key(source_key, key);

    for (size_t current = 0; current < block_count; ++current) {
        uint64_t block {};
        in_file.read(reinterpret_cast<char*>(&block), sizeof(block));


        block = feistel(block, key, ROUNDS, decrypt);

        size_t write_size = sizeof(block);
        if (decrypt and current == block_count - 1)
            write_size = file_size % sizeof(block);

        if (write_size == 0) write_size = sizeof(block);

        out_file.write(reinterpret_cast<char*>(&block), write_size);

        if (int(current * bar_max / block_count) > bar_current) {
        	bar_current = current * bar_max / block_count;
        	draw_bar(bar_current, bar_max);
        }

    }

    in_file.close();
    out_file.close();

}


int main(int argc, char ** argv)
{
    if (argc < 5) {
        std::cout << "Usage: " <<
                basename(argv[0]) <<
                " <command> <key> <input file> <output file>" <<
                std::endl;
    }
    const char * source_key  = argv[2];
    const char * input_filename  = argv[3];
    const char * output_filename = argv[4];

    switch (argv[1][0]) {
        case 'e': // Зашифровать
            std::cout << "Encryption" << std::endl;
            file_crypt(input_filename, output_filename, source_key, false);
            break;
        case 'd': // Расшифровать
            std::cout << "Decryption" << std::endl;
            file_crypt(input_filename, output_filename, source_key, true);
            break;
        default:
            std::cerr << "Неизвестная команда - " << argv[1] << std::endl;
    }

    return 0;
}
