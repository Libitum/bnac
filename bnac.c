#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>

#define BUFFER_SIZE 8192

static const char* user = "username";
static const char* pass = "password";

static const char* host = "172.22.1.144";
static const int port = 10001;

// get from PEM public key
static const char* rsa_key = 
	"ACCE3743572D4D0F291E9E5D5BCC64166E6189E1339BDD8C071E8CD6E55FF156"
	"B742BB79ACB7172BE61B154C8DFE8005079868A71D106D638CDA18A886FC6923"
	"E1C1EAB879A7F43F6309A6D6D0374FF19DBEDB73163840C839E74E263F3BAD66"
	"FA1A048AF6AF0DCC4BB6467874DCBF9F57DE23BCC373AD4B3F8D12F801B9F906"
	"F2E87C8D7AD9160BC874D45C16F079B7098EAF7C40C9DC73ECA8328C9D4697FC"
	"FAA82AFF1FDAC50597F99C433D7C2C7D09370343E2A354A88F81AA934A26CBAD"
	"A64381E9D180F5D5D0B5319CD9BCE8E483F11AC4ABC494B4D534A3A8FA004A84"
	"63F182952122471F09156EE9FEAF9C31E4E2ED10570CC718772C42E02160E469";

static const char* aes_key_str = "\x16\x25\x3A\x48\x55\x69\x77\x8C\x94\xA7\xBE\xC1\xD4\xE2\xFD\x11";

static const int xor_key[11][2] = {{0, 0}, {1, 2}, {3, 5}, {9, 1}, {2, 7}, {1, 3}, {5, 6}, {7, 8}, {8, 9}, {3, 7}, {4, 6}};

void xor(char* d, int size, int k) {
	int a = xor_key[k][0];
	int b = xor_key[k][1];
	int c;
	int i;
	for (i = 0; i < size; ++i) {
		c = (a + b) % 0xFF;
		*d = *d ^ c;
		a = b;
		b = c;
		d++;
	}
}

/**
 * encrypt wich xor.  why not rsa?
 */
size_t encrypt(const char* in, char* out, int k) {
	memset(out, 0, BUFFER_SIZE);

	AES_KEY aes_key;
	AES_set_encrypt_key((unsigned char*)aes_key_str, 128, &aes_key);
	// length of content for aes must be a multiple of 16 in length
	size_t size = (strlen(in) + 15) / 16 * 16;
	char* tmp = (char*)malloc(size);
	memset(tmp, 0, size);
	strcpy(tmp, in);

	// get length
	uint32_t length = strlen(in);
	memcpy(out, &length, sizeof(uint32_t));

	// xor
	xor(tmp, size, k);

	// because AES_encrypt can only encrypts 16 bytes every time.
	char* enc_in = tmp;
	char* enc_out = out + sizeof(uint32_t);
	size_t enc_length = 0;
	while (enc_length < size) {
		AES_encrypt((unsigned char*)enc_in, (unsigned char*)enc_out, &aes_key);
		enc_in     += AES_BLOCK_SIZE;
		enc_out    += AES_BLOCK_SIZE;
		enc_length += AES_BLOCK_SIZE;
	}

	free(tmp);

	return sizeof(uint32_t) + size;
}

size_t decrypt(const char* in, char* out, int k) {
	memset(out, 0, BUFFER_SIZE);

	AES_KEY aes_key;
	AES_set_decrypt_key((unsigned char*)aes_key_str, 128, &aes_key);

	size_t size = 0;
	memcpy(&size, in, sizeof(uint32_t));

	const char* enc_in = in + sizeof(uint32_t);
	char* enc_out = out;
	size_t enc_length = 0;
	while (enc_length < size) {
		AES_decrypt((unsigned char*)enc_in, (unsigned char*)enc_out, &aes_key);
		enc_in     += AES_BLOCK_SIZE;
		enc_out    += AES_BLOCK_SIZE;
		enc_length += AES_BLOCK_SIZE;
	}
	
	xor(out, size, k);
	return size;
}

void rsa_encrypt(const char* in, char* out) {
	memset(out, 0, BUFFER_SIZE);

	RSA *rsa = RSA_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();

    BN_hex2bn(&n, rsa_key);
    BN_set_word(e, 65537);
    rsa->n = n;
    rsa->e = e;

    size_t size = RSA_size(rsa);
    char* tmp = (char*)malloc(size);
    memset(tmp, 0, size);

    RSA_public_encrypt(strlen(in), (unsigned char*)in, (unsigned char*)tmp, rsa, RSA_PKCS1_PADDING);

    int i = 0;
    for (i = 0; i < size; ++i)
    {
    	sprintf(out + i * 2, "%02hhx", (unsigned char)tmp[i]);
    }

	free(tmp);
    rsa->n = NULL;
    rsa->e = NULL;
    BN_free(n);
    BN_free(e);
    RSA_free(rsa);
}

void get_socket_md5(int socket_fd, const char* session_id, char* out) {
	memset(out, 0, BUFFER_SIZE);

	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	getsockname(socket_fd, &addr, &addrlen);

	char socket_name[256];
	memset(socket_name, 0, sizeof(socket_name));
	inet_ntop(AF_INET, &addr, socket_name, sizeof(addr));

	char buf[BUFFER_SIZE];
	sprintf(buf, "liuyan:%s:%s", session_id, socket_name);
	MD5((unsigned char*)buf, strlen(buf), (unsigned char*)out);
}

int connect_server() {
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		return -1;
	}

	struct sockaddr_in remote_addr;
	memset(&remote_addr, 0, sizeof(remote_addr));

	remote_addr.sin_family = AF_INET;
	remote_addr.sin_addr.s_addr = inet_addr(host);
	remote_addr.sin_port = htons(port);

	if (connect(socket_fd, (struct sockaddr*)&remote_addr, sizeof(struct sockaddr)) == 0) {
		return socket_fd;
	}
	else {
		return -1;
	}
}

int auth(int socket_fd, const char* username, const char* password, char* session_id, int* xor) {
	char buf1[BUFFER_SIZE];
	char buf2[BUFFER_SIZE];
	size_t size;
	char uuid_str[40];
	uuid_t uuid;

	// step1: send ASK_ENCODE and get xor key
	// generate uuid used as client id
	uuid_generate(uuid);
	uuid_unparse_upper(uuid, uuid_str);

	snprintf(buf1, BUFFER_SIZE, "ASK_ENCODE\r\nPLATFORM:MAC\r\nVERSION:1.0.1.22\r\nCLIENTID:BNAC_{%s}\r\n\r\n", uuid_str);
	if (send(socket_fd, buf1, strlen(buf1), 0) <= 0) {
		fprintf(stderr, "send ASK_ENCODE failed.\n");
		return -11;
	}

	if (recv(socket_fd, buf1, BUFFER_SIZE, 0) <= 0) {
		fprintf(stderr, "recv ASK_ENCODE failed\n");
		return -12;
	}
	
	int xor_num;
	int code = 0;
	if (sscanf(buf1, "%d\r\nCIPHERNUM:%d", &code, &xor_num) != 2 || code != 601) {
		fprintf(stderr, "get nCIPHERNUM failed when ASK_ENCODE\n");
		return -13;
	}

	// step2: send OPEN_SESAME
	snprintf(buf1, BUFFER_SIZE, "OPEN_SESAME\r\nSESAME_MD5:INVALID MD5\r\n\r\n");
	size = encrypt(buf1, buf2, xor_num);
	if (send(socket_fd, buf2, size, 0) <= 0) {
		fprintf(stderr, "send OPEN_SESAME failed.\n");
		return -21;
	}

	if (recv(socket_fd, buf1, BUFFER_SIZE, 0) <= 0) {
		fprintf(stderr, "recv OPEN_SESAME failed.\n");
		return -22;
	}

	size = decrypt(buf1, buf2, xor_num);
	if (sscanf(buf2, "%d\r\n", &code) != 1 || code != 603) {
		fprintf(stderr, "get OPEN_SESAME failed\n");
		return -23;
	}

	// step3: send SESAME_VALUE
	snprintf(buf1, BUFFER_SIZE, "SESAME_VALUE\r\nVALUE:0\r\n\r\n");
	size = encrypt(buf1, buf2, xor_num);
	if (send(socket_fd, buf2, size, 0) <= 0) {
		fprintf(stderr, "send SESAME_VALUE failed.\n");
		return -31;
	}

	if (recv(socket_fd, buf1, BUFFER_SIZE, 0) <= 0) {
		fprintf(stderr, "recv SESAME_VALUE failed.\n");
		return -32;
	}

	size = decrypt(buf1, buf2, xor_num);
	if (sscanf(buf2, "%d\r\n", &code) != 1 || code != 604) {
		fprintf(stderr, "get SESAME_VALUE failed\n");
		return -33;
	}

	// step4: send AUTH
	rsa_encrypt(password, buf2);
	snprintf(buf1, BUFFER_SIZE, "AUTH\r\nOS:MAC\r\nUSER:%s\r\nPASS:%s\r\nAUTH_TYPE:DOMAIN\r\n\r\n",
		username, buf2);
	size = encrypt(buf1, buf2, xor_num);
	if (send(socket_fd, buf2, size, 0) <= 0) {
		fprintf(stderr, "send AUTH failed.\n");
		return -41;
	}

	if (recv(socket_fd, buf1, BUFFER_SIZE, 0) <= 0) {
		fprintf(stderr, "recv AUTH failed.\n");
		return -42;
	}

	size = decrypt(buf1, buf2, xor_num);
	int role = 0;
	if (sscanf(buf2, "%d\r\nSESSION_ID:%s\r\nROLE:%d\r\n", &code, session_id, &role) != 3 || code != 288) {
		fprintf(stderr, "get SESSION_ID or role failed\n");
		return -43;
	}

	// step5: push
	get_socket_md5(socket_fd, session_id, buf2);
	snprintf(buf1, BUFFER_SIZE, "PUSH\r\nTIME:%s\r\nSESSIONID:%s\r\nROLE:%d\r\n\r\n", buf2, session_id, role);
	size = encrypt(buf1, buf2, xor_num);
	if (send(socket_fd, buf2, size, 0) <= 0) {
		fprintf(stderr, "send PUSH failed.\n");
		return -51;
	}

	if (recv(socket_fd, buf1, BUFFER_SIZE, 0) <= 0) {
		fprintf(stderr, "recv PUSH failed.\n");
		return -52;
	}
	size = decrypt(buf1, buf2, xor_num);
	if (sscanf(buf2, "%d\r\n", &code) != 1 || code != 220) {
		fprintf(stderr, "push session failed\n");
		return -53;
	}

	*xor = xor_num;
	return 0;
}

int keep_alive(int socket_fd, const char* user, const char* session_id, int xor_num) {
	static int heartbeat = 1;
	char buf1[BUFFER_SIZE];
	char buf2[BUFFER_SIZE];

	snprintf(buf1, BUFFER_SIZE, "KEEP_ALIVE\r\nSESSIONID:%s\r\nUSER:%s\r\nAUTH_TYPE:DOMAIN\r\nHEARTBEAT_INDEX:%d\r\n\r\n", 
		session_id, user, heartbeat);
	size_t size = encrypt(buf1, buf2, xor_num);
	if (send(socket_fd, buf2, size, 0) <= 0) {
		fprintf(stderr, "send KEEP_ALIVE failed.\n");
		return -1;
	}

	return 0;
}

int main(int argc, char const *argv[])
{
	daemon(0, 0);

	char session_id[32];
	int xor_num;
	short step = 0;

	int socket_fd;

	do {
		if (step == 0 && (socket_fd = connect_server()) != -1) {
			step ++;
		}

		if (step == 1 && auth(socket_fd, user, pass, session_id, &xor_num) == 0) {
			step ++;
		}

		sleep(60);

		if (step == 2) {
			if (keep_alive(socket_fd, user, session_id, xor_num) != 0) {
				close(socket_fd);
				step = 0;
			}
		}
		
	} while(1);

	return 0;
}
