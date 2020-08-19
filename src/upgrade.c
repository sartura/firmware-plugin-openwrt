
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <sysrepo.h>

#include <json-c/json.h>
#include <libubox/md5.h>

#include "upgrade.h"
#include "firmware.h"

const char file_path[FILENAME_MAX] = "/tmp/sr_firmware.bin";

void delete_firmware(const char *filename)
{
	int ret;

	ret = remove(filename);

	if (ret == 0) {
		SRP_LOG_INF("Deleted firmware %s.", filename);
	} else {
		SRP_LOG_ERR("Couldn't delete firmware %s.", filename);
	}
}

bool compare_firmware_checksum(plugin_ctx_t *ctx, firmware_t *firmware)
{
	const char *filename = "/etc/sysrepo/sysupgrade/cksum";
	bool equal = false;
	size_t max_buf_len = 64;

	char source[max_buf_len + 1];
	FILE *file = fopen(filename, "r");
	if (NULL == file) {
		SRP_LOG_ERRMSG("fopen returned NULL");
		goto cleanup;
	}

	size_t newLen = fread(source, sizeof(char), max_buf_len, file);
	if (ferror(file) != 0) {
		SRP_LOG_ERRMSG("error reading file");
		goto cleanup;
	}

	source[newLen++] = '\0';
	if (0 == strncmp(firmware->checksum.value, source, strlen(firmware->checksum.value))) {
		equal = true;
	}

	if (true == equal) {
		SET_STR(ctx->running_software.uri, firmware->source.uri);
		SET_MEM_STR(ctx->running_software.status, "installed");
		SET_MEM_STR(ctx->running_software.message, "");
	}

cleanup:
	if (NULL != file) {
		fclose(file);
	}

	return equal;
}

static int update_checksum(firmware_t *firmware)
{
	FILE *file;
	int rc = SR_ERR_OK;
	const char *filename = "/etc/sysrepo/sysupgrade/cksum";

	file = fopen(filename, "w+b");
	// CHECK_NULL_MSG(file, &rc, cleanup, "fopen returned NULL");
	if (file == NULL) {
		SRP_LOG_ERRMSG("fopen returned NULL");
		rc = SR_ERR_INTERNAL;
		goto cleanup;
	}

	char *cksum = firmware->checksum.value;

	fprintf(file, "%s", cksum);

cleanup:
	if (NULL != file) {
		fclose(file);
	}

	return rc;
}

int copy_file(char *src_path, char *dst_path)
{

	int src_fd, dst_fd, n, err;
	unsigned char buffer[4096];

	src_fd = open(src_path, O_RDONLY);
	dst_fd = open(dst_path, O_CREAT | O_WRONLY);

	while (1) {
		err = read(src_fd, buffer, 4096);
		if (err == -1) {
			goto error;
		}
		n = err;

		if (n == 0)
			break;

		err = write(dst_fd, buffer, n);
		if (err == -1) {
			goto error;
		}
	}

	close(src_fd);
	close(dst_fd);

	return 0;
error:
	SRP_LOG_ERR("failed to copy file %s to %s", src_path, dst_path);
	close(src_fd);
	close(dst_fd);
	return 1;
}

static void generate_startup_data(firmware_t *firmware)
{
	char *filename = "/etc/sysrepo/sysupgrade/ietf-system.startup";
	FILE *file = NULL;

	file = fopen(filename, "w+b");
	if (NULL == file) {
		goto out_error;
	}

	fprintf(file, "<system xmlns=\"urn:ietf:params:xml:ns:yang:ietf-system\">\n");
	fprintf(file, "  <software xmlns=\"http://terastrm.net/ns/yang/terastream-software\">\n");
	fprintf(file, "    <software>\n");
	if (NULL != firmware->source.uri) {
		fprintf(file, "      <source>%s</source>\n", firmware->source.uri);
	}
	if (NULL != firmware->credentials.value) {
		fprintf(file, "      <password>\n");
		fprintf(file, "        <password>%s</password>\n", firmware->credentials.value);
		fprintf(file, "      </password>\n");
	}
	if (NULL != firmware->checksum.value) {
		fprintf(file, "      <checksum>\n");
		switch (firmware->checksum.type) {
			case CKSUM_MD5:
				fprintf(file, "        <type>%s</type>\n", "md5");
				break;
			case CKSUM_SHA1:
				fprintf(file, "        <type>%s</type>\n", "sha-1");
				break;
			case CKSUM_SHA2:
				fprintf(file, "        <type>%s</type>\n", "sha-2");
				break;
			case CKSUM_SHA3:
				fprintf(file, "        <type>%s</type>\n", "sha-3");
				break;
			case CKSUM_SHA256:
				fprintf(file, "        <type>%s</type>\n", "sha-256");
				break;
		}
		fprintf(file, "        <value>%s</value>\n", firmware->checksum.value);
		fprintf(file, "      </checksum>\n");
	}
	if (true == firmware->preserve_configuration) {
		fprintf(file, "      <preserve-configuration>true</preserve-configuration>\n");
	} else {
		fprintf(file, "      <preserve-configuration>false</preserve-configuration>\n");
	}

	fprintf(file, "    </software>\n");
	fprintf(file, "  </software>\n");
	fprintf(file, "</system>\n");

out_error:
	if (NULL != file) {
		fclose(file);
	}

	/* save ietf-keystore config file */
	char *src_path = "/etc/sysrepo/data/ietf-keystore.startup";
	char *dst_path = "/etc/sysrepo/sysupgrade/ietf-keystore.startup";
	copy_file(src_path, dst_path);

	return;
}

static char *get_username_from_url(char *url)
{
	char *res = malloc(sizeof(char) * strlen(url));
	unsigned int i, counter = 0;
	int bIndex = 0, eIndex = 0;

	for (i = 0; i < strlen(url); i++) {
		if (url[i] == '/') {
			++counter;
		}
		if (url[i] == '/' && counter == 2) {
			bIndex = i;
		}
		if (url[i] == '@' && counter == 2) {
			eIndex = i;
		}
	}

	if (bIndex > 0 && eIndex > 0) {
		strncpy(res, url + bIndex, eIndex - bIndex);
		free(res);
		res = NULL;
	}

	return res;
}

struct server_data {
	char *address;
	char *password;
	char *certificate;
	char *ssh_key;
};

struct curl_ctx {
	firmware_t *firmware;
	struct server_data *server;
	const char *path;
	size_t n_filesize;
	size_t n_downloaded;
	/* datastore_t *progress; */
	FILE *stream;
};

static size_t firmware_write_cb(void *buffer, size_t size, size_t nmemb, FILE *stream)
{
	return fwrite(buffer, size, nmemb, stream);
}

static CURLcode firmware_download_ssl(CURL *curl, void *sslctx, void *parm)
{
	/* X509_STORE *store; */
	/* X509 *cert=NULL; */
	/* BIO *bio; */
	/* char *mypem = NULL; */

	/* struct curl_data *data = (struct curl_data *)parm; */
	/* mypem = (char *) data->server->certificate; */

	/* bio = BIO_new_mem_buf(mypem, -1); */

	/* PEM_read_bio_X509(bio, &cert, 0, NULL); */
	/* if (NULL == cert) */
	/*     DEBUG("PEM_read_bio_X509 failed...\n"); */

	/* store=SSL_CTX_get_cert_store((SSL_CTX *) sslctx); */

	/* if (0 == X509_STORE_add_cert(store, cert)) */
	/*     DEBUG("error adding certificate\n"); */

	/* X509_free(cert); */
	/* BIO_free(bio); */

	return CURLE_OK;
}

static char *get_sha256()
{
	unsigned char buffer[4096];
	char sha256[SHA256_DIGEST_LENGTH * 2 + 1];
	FILE *f;
	SHA256_CTX ctx;
	size_t len;
	f = fopen(file_path, "r");
	if (!f) {
		SRP_LOG_ERR("Couldn't open firmware %s", file_path);
		return NULL;
	}
	SHA256_Init(&ctx);
	do {
		len = fread(buffer, sizeof(unsigned char), sizeof(buffer), f);
		if (len > 0) {
			SHA256_Update(&ctx, buffer, len);
		}
	} while (len > 0);

	SHA256_Final(buffer, &ctx);
	fclose(f);

	for (len = 0; len < SHA256_DIGEST_LENGTH; len++) {
		sprintf(&sha256[len * 2], "%02x", (unsigned int) buffer[len]);
	}

	return strdup(sha256);
}

static char *get_md5sum()
{
	char md5_str[33];
	uint8_t md5[16];
	int n;

	if (0 >= md5sum((char *) file_path, md5)) {
		return NULL;
	}

	for (n = 0; n < 16; n++) {
		sprintf(&md5_str[n * 2], "%02x", (unsigned int) md5[n]);
	}

	SRP_LOG_INF("Checksum is %s", md5_str);
	return strdup(md5_str);
}

static bool checksum_check(firmware_t *firmware)
{
	char *cksum = NULL;
	bool match = false;

	switch (firmware->checksum.type) {
		case (CKSUM_MD5):
			cksum = get_md5sum();
			break;
		case (CKSUM_SHA1):
		case (CKSUM_SHA2):
		case (CKSUM_SHA3):
		case (CKSUM_SHA256):
			cksum = get_sha256();
			break;
	}

	if (NULL == cksum || NULL == firmware->checksum.value) {
		goto cleanup;
	}

	if (0 == strcmp(cksum, firmware->checksum.value) && strlen(cksum) == strlen(firmware->checksum.value)) {
		match = true;
	} else {
		SRP_LOG_ERRMSG("cheksum does not match");
		SRP_LOG_INF("calculated checksum is %s", cksum);
		SRP_LOG_INF("expected checksum is %s", firmware->checksum.value);
	}

cleanup:
	if (cksum) {
		free(cksum);
	}
	return match;
}

int download_firmware(plugin_ctx_t *ctx)
{
	CURL *curl;
	CURLcode curl_ret;
	int rc = SR_ERR_OK;
	FILE *fd_data = NULL;
	const char *cert_type = "PEM";
	const char *public_keyfile_path = "";
	uint32_t download_attempts = 0;

	delete_firmware(file_path);

	/* open file */
	fd_data = fopen(file_path, "wb");
	if (NULL == fd_data) {
		rc = SR_ERR_INTERNAL;
		goto cleanup;
	}

	curl = curl_easy_init();
	if (!curl) {
		goto cleanup;
	}

	switch (ctx->firmware.credentials.type) {
		case (CRED_PASSWD):;
			char *username = get_username_from_url(ctx->firmware.source.uri);
			char *cred = NULL;
			if (NULL != username && NULL != ctx->firmware.credentials.value) {
				cred = malloc(sizeof(char) * strlen(username) + strlen(ctx->firmware.credentials.value) + 2);
				sprintf(cred, "%s:%s", username, ctx->firmware.credentials.value);
				free(username);
				free(cred);
			} else {
				cred = strdup(ctx->firmware.credentials.value ? ctx->firmware.credentials.value : "");
			}
			curl_easy_setopt(curl, CURLOPT_USERPWD, cred);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_write_cb);
			free(cred);
			break;
		case (CRED_CERT):
			curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, cert_type);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, firmware_download_ssl);
			break;
		case (CRED_SSH_KEY):
			curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, 0);
			curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PUBLICKEY);
			curl_easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, public_keyfile_path);
			curl_easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, public_keyfile_path);
			curl_easy_setopt(curl, CURLOPT_DIRLISTONLY, 1);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_write_cb);
	}

	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_URL, ctx->firmware.source.uri);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fd_data);

	// set libcurl timeout to 10 minuts
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (10 * 60));

	while (0 == ctx->firmware.policy.download_attempts ||
		   (0 < ctx->firmware.policy.download_attempts && download_attempts < ctx->firmware.policy.download_attempts)) {
		SRP_LOG_INFMSG("downloading");
		SET_MEM_STR(ctx->installing_software.status, "downloading");
		download_attempts++;

		SET_MEM_STR(ctx->installing_software.message, "starting download with libcurl");
		curl_ret = curl_easy_perform(curl);

		SET_MEM_STR(ctx->installing_software.message, "libcurl finished");
		if (CURLE_OK == curl_ret) {
			long http_code = 0;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
			if (http_code == 200 && curl_ret != CURLE_ABORTED_BY_CALLBACK) {
				SRP_LOG_INFMSG("download-done");
				SET_MEM_STR(ctx->installing_software.status, "download-done");
				break;
			} else {
				SRP_LOG_INFMSG("dl-verification-failed");
				SET_MEM_STR(ctx->installing_software.status, "dl-verification-failed");
				char message[30] = {0};
				sprintf(message, "libcurl returned error code %ld", http_code);
				SET_MEM_STR(ctx->installing_software.message, message);
			}
		}
		SRP_LOG_INFMSG("downloading-failed");
		SET_MEM_STR(ctx->installing_software.status, "download-failed");
		uint32_t time = ctx->firmware.policy.retry_interval + (rand() % ctx->firmware.policy.retry_randomness);
		SRP_LOG_INF("wait for %d seconds", time);
		char message[120];
		sprintf(message, "download failed, starting new attempt in %d seconds", time);
		SET_MEM_STR(ctx->installing_software.message, message);

		/* close the file */
		fclose(fd_data);
		fd_data = NULL;
		/* delete the file */
		delete_firmware(file_path);
		/* wait */
		sleep(time);
		/* open file */
		fd_data = fopen(file_path, "wb");
		if (NULL == fd_data) {
			rc = SR_ERR_INTERNAL;
			goto cleanup;
		}
	}

	/* close the firmware image file */
	fclose(fd_data);
	fd_data = NULL;

	/* checksum checke */
	if (true == checksum_check(&ctx->firmware)) {
		SET_MEM_STR(ctx->installing_software.message, "correct checksum");
	} else {
		SET_MEM_STR(ctx->installing_software.message, "wrong checksum");
		rc = SR_ERR_INTERNAL;
	}

cleanup:
	if (fd_data) {
		fclose(fd_data);
	}
	curl_easy_cleanup(curl);

	if (SR_ERR_OK != rc) {
		delete_firmware(file_path);
	}

	return rc;
}

int install_firmware(plugin_ctx_t *ctx)
{
	int rc = SR_ERR_OK;
	char result[1024] = {0};
	char command[128] = {0};
	FILE *file = NULL;

	sprintf(command, "/sbin/sysupgrade -T %s", file_path);

	/* perform sysupgrade check */
	file = popen(command, "r");
	if (NULL == file) {
		SRP_LOG_ERR("could not run command %s", command);
	}

	while (fgets(result, sizeof(result) - 1, file) != NULL) {
	}
	result[strlen(result) - 1] = '\0';
	int status = pclose(file);

	/* image check failed */
	if (0 != WEXITSTATUS(status)) {
		if (0 < strlen(result)) {
			SRP_LOG_ERR("upgrade faild with message:%s", result);
			SET_MEM_STR(ctx->installing_software.message, result);
			SET_MEM_STR(ctx->installing_software.status, "upgrade-failed");
		}
		return SR_ERR_INTERNAL;
	}

	SET_MEM_STR(ctx->installing_software.status, "upgrade-in-progress");
	SET_MEM_STR(ctx->installing_software.message, "starting sysupgrade call");

	if (true == ctx->firmware.preserve_configuration) {
		/* if /etc/sysrepo/sysupgrade does not exist, create it */
		const char *dir = "/etc/sysrepo/sysupgrade";
		struct stat st = {0};

		if (stat(dir, &st) == -1) {
			mkdir(dir, 0700);
		}

		generate_startup_data(&ctx->firmware);
		update_checksum(&ctx->firmware);
		sprintf(command, "/sbin/sysupgrade %s", file_path);
	} else {
		sprintf(command, "/sbin/sysupgrade -n %s", file_path);
	}

	/* perform sysupgrade check */
	system(command);

	SET_MEM_STR(ctx->installing_software.status, "upgrade-done");

	return rc;
}
