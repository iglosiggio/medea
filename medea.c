#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

#include <zstd.h>

#define MB (1024L * 1024L)

struct bounded_buf {
	void* buf;
	long siz;
	long capacity;
};

struct program {
	uint16_t* SIN;
	uint16_t* SCODE;
	uint16_t* SMAIN;
	uint16_t SIN_len;
	uint16_t SCODE_len;
	uint16_t SMAIN_len;
} challenge_program = {
	NULL, NULL, NULL,
	-1, -1, -1
};


#define FZERO (1<<0)
#define FEQUL (1<<1)
#define FLT   (1<<2)
#define FGT   (1<<3)
#define FCRRY (1<<4)
#define FINF  (1<<5)
#define FSE   (1<<6)
#define FSF   (1<<7)

struct medea_state {
	/* General purpose */
	uint16_t RX, RY, RZ;
	/* Target register */
	uint16_t RTRGT;
	/* Flags register */
	uint16_t RSTAT;
	/* Call register */
	uint16_t RCALL;
	/* Stack pointer register */
	uint16_t RSK;
	/* Stack return register */
	uint16_t RSR;
	/* Stack space */
	uint16_t SSK[65536];
	/* Input memory space */
	uint16_t* SIN;
	/* General purpose memory space */
	uint16_t* SMAIN;
	/* Code memory space */
	uint16_t* SCODE;
	uint16_t IP;
} medea_state = {
	.RSTAT = FSE,
	.RSK   = 0xFFFF,
	.IP    = 0x0001
};

/* Instructions */
enum medea_opcode {
	HALT, NOOP, INC, DEC, ADD, SUB, MUL, DIC, ADDC, SUBC, READ, WRIT, CPY,
	MCPY, ICPY, CMP, AND, OR, CMPL, LSHF, RSHF, PUSH, POP, CFLG, CALL,
	RTRN, RTRV, RTL, RTR, CIP, BSWP, JUMP, JZRO, JEQU, JLT, JGT, JCRY,
	JINF, JSE, JSF,
	CZRO = 0x030,
	CCRY = 0x034,
	XOR  = 0x40,
	SWAP, RCPT, RCPF,
	MEDEA_OPCODE_END
};

int medea_opcode_argcount[] = {
	0, 0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 1, 2, 3, 2, 2, 2, 2, 1, 2, 2, 1, 1, 0,
	3, 0, 0, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	[CZRO] = 0,
	[CCRY] = 0,
	[XOR]  = 2, 2, 2, 2,
	/* MEDEA_OPCODE_END */ 0
};

const char* medea_opcode_name[] = {
	"HALT", "NOOP", "INC", "DEC", "ADD", "SUB", "MUL", "DIC", "ADDC",
	"SUBC", "READ", "WRIT", "CPY", "MCPY", "ICPY", "CMP", "AND", "OR",
	"CMPL", "LSHF", "RSHF", "PUSH", "POP", "CFLG", "CALL", "RTRN", "RTRV",
	"RTL", "RTR", "CIP", "BSWP", "JUMP", "JZRO", "JEQU", "JLT", "JGT",
	"JCRY", "JINF", "JSE", "JSF",
	[CZRO] = "CZRO",
	[CCRY] = "CCRY",
	[XOR]  = "XOR",
	"SWAP", "RCPT", "RCPF",
	/* MEDEA_OPCODE_END */ "error"
};

struct medea_instr {
	uint8_t  AFLG0;
	uint8_t  AFLG1;
	uint8_t  AFLG2;
	uint8_t  SIGN;
	uint16_t OPCODE;
};

struct medea_instr instr_from_bits(uint16_t bits) {
	return (struct medea_instr) {
		.AFLG0   = bits >> 14 & 0x3,
		.AFLG1   = bits >> 12 & 0x3,
		.AFLG2   = bits >> 10 & 0x3,
		.SIGN    = bits >>  9 & 0x1,
		.OPCODE  = bits >>  0 & 0x1ff
	};
}

struct medea_args {
	uint8_t idx0;
	uint8_t idx1;
	uint8_t idx2;
	uint8_t reserved;
};

struct medea_args args_from_bits(uint16_t bits) {
	return (struct medea_args) {
		.idx0     = bits >> 12 & 0xF,
		.idx1     = bits >>  8 & 0xF,
		.idx2     = bits >>  4 & 0xF,
		.reserved = bits >>  0 & 0x1,
	};
}

void print_opcodes() {
	uint16_t* code     = challenge_program.SCODE;
	uint16_t  code_len = challenge_program.SCODE_len;
	uint16_t  cur      = 0;

	assert(challenge_program.SCODE != NULL);

	while (cur < code_len) {
		struct medea_instr instr = instr_from_bits(code[cur]);
		unsigned opcode_name_idx = instr.OPCODE;
		unsigned has_second_word = 0;

		if (opcode_name_idx > MEDEA_OPCODE_END)
			opcode_name_idx = MEDEA_OPCODE_END;
		if (medea_opcode_name[opcode_name_idx]  == NULL)
			opcode_name_idx = MEDEA_OPCODE_END;

		printf("[%s]\t", medea_opcode_name[opcode_name_idx]);
		printf(
			"%x %x %x %x %x",
			instr.AFLG0, instr.AFLG1, instr.AFLG2, instr.SIGN,
			instr.OPCODE
		);

		if (medea_opcode_argcount[instr.OPCODE] >= 1)
			has_second_word |= (instr.AFLG0 & 2) == 0;

		if (medea_opcode_argcount[instr.OPCODE] >= 2)
			has_second_word |= (instr.AFLG1 & 2) == 0;

		if (medea_opcode_argcount[instr.OPCODE] >= 3)
			has_second_word |= (instr.AFLG2 & 2) == 0;

		cur += 1;

		if (has_second_word) {
			struct medea_args args = args_from_bits(code[cur]);

			printf("\t| %x %x %x %x", args.idx0, args.idx1, args.idx2);
			cur += 1;
		}

		puts("");
	}
}

void print_scode() {
	uint16_t* code = challenge_program.SCODE;
	uint16_t cur = 0;

	assert(challenge_program.SCODE != NULL);

	while (cur < challenge_program.SCODE_len) {
		if ((cur % 8) == 7)
			printf("%.4x\n", code[cur]);
		else
			printf("%.4x ", code[cur]);
		cur++;
	}
}

struct bounded_buf read_entire_file(const char* filepath) {
	FILE* file;
	struct bounded_buf buf;
	long filesiz;

	file = fopen(filepath, "r");
	assert(file != NULL);

	fseek(file, 0L, SEEK_END);
	filesiz = ftell(file);
	rewind(file);

	buf.buf = malloc(filesiz);
	buf.capacity = filesiz;
	assert(buf.buf != NULL);

	buf.siz = fread(buf.buf, 1, filesiz, file);
	assert(buf.siz == filesiz);
	fclose(file);

	return buf;
}

struct bounded_buf decompress(const struct bounded_buf input) {
	struct bounded_buf decompressed;

	decompressed.capacity = 2 * MB;
	decompressed.buf = malloc(decompressed.capacity);
	decompressed.siz = ZSTD_decompress(
		decompressed.buf, decompressed.capacity,
		input.buf + 4, input.siz - 4	// Skip mCTZ header
	);

	return decompressed;
}

void load_program(const struct bounded_buf image) {
	static const char* chunk_kinds[] = {
		"SERROR",
		"SIN   ",
		"SCODE ",
		"SMAIN "
	};

	long cur = 0;

	while (cur < image.siz) {
		uint8_t kind;
		uint16_t length;
		
		kind   = *(uint8_t*)(image.buf + cur);
		cur   += 1;
		length = *(uint16_t*)(image.buf + cur);
		cur   += 2;

		if (kind > 3)
			kind = 0;

		if (kind == 1) {
			challenge_program.SIN     = image.buf + cur;
			challenge_program.SIN_len = length;
		}

		if (kind == 2) {
			challenge_program.SCODE     = image.buf + cur;
			challenge_program.SCODE_len = length;
		}

		if (kind == 3) {
			challenge_program.SMAIN     = image.buf + cur;
			challenge_program.SMAIN_len = length;
		}

		printf("Section %s [SIZE %d]\n", chunk_kinds[kind], length * 2);

		cur += length * 2;
	}
}

int main(int argc, char* argv[]) {
	struct bounded_buf file = read_entire_file("challenge.mctf");

	puts("=== COMPRESSED ===");
	printf("siz    = %ld\n", file.siz);
	printf("buf    = %p\n", file.buf);
	printf("header = %.4s\n", (const char*) file.buf);

	struct bounded_buf decompressed = decompress(file);
	puts("=== DECOMPRESSED ===");
	printf("siz    = %ld\n", decompressed.siz);
	printf("buf    = %p\n", decompressed.buf);
	printf("header = %.4s\n", (const char*) decompressed.buf);

	printf("sizeof(struct medea_instr) = %ld\n", sizeof(struct medea_instr));
	printf("sizeof(struct medea_args)  = %ld\n", sizeof(struct medea_args));

	puts("");
	puts("=== SECTIONS ===");
	puts("");
	load_program(decompressed);
	puts("");
	puts("=== SCODE HEXDUMP ===");
	puts("");
	print_scode();
	puts("");
	puts("=== SCODE LISTING ===");
	puts("");
	print_opcodes();

	return 0;
}
