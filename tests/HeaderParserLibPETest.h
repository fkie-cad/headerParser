#ifndef G_TESTS_HEADER_PARSER_HEADER_PARSER_LIB_PE_TEST
#define G_TESTS_HEADER_PARSER_HEADER_PARSER_LIB_PE_TEST

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <fstream>
#include <sstream>

#include <gtest/gtest.h>

#include "../src/headerDataHandler.h"
#include "../src/headerParserLibPE.h"
#include "../src/pe/PEHeaderParser.h"

using namespace std;

class HeaderParserLibPETest : public testing::Test
{
	protected:
		const string tmp_prefix = "HeaderParserLibPETest";

		const char* pe_file = "tests/files/qappsrv.exe";
		const char* pe_file_with_cert = "/path/to/file/with/cert.exe";
		const char* elf_file = "tests/files/hello_world_release.elf";

		unsigned char block_s[BLOCKSIZE];
		unsigned char block_l[BLOCKSIZE_LARGE];

		static string getTempDir(const std::string& prefix)
		{
			string tmp = "/tmp/"+prefix+"XXXXXX";
			char* buf = &tmp[0];
			char* dir = mkdtemp(buf);

			return string(dir);
		}

		PEHeaderData* getInitializedPEHeaderData()
		{
			PEHeaderData* pehd = NULL;

			pehd = (PEHeaderData*) calloc(1, sizeof(PEHeaderData));
			if ( pehd == NULL )
				return NULL;

			pehd->image_dos_header = (PEImageDosHeader*) calloc(1, sizeof(PEImageDosHeader));
			pehd->coff_header = (PECoffFileHeader*) calloc(1, sizeof(PECoffFileHeader));
			pehd->opt_header = (PE64OptHeader*) calloc(1, sizeof(PE64OptHeader));
			if ( pehd->image_dos_header == NULL || pehd->coff_header == NULL || pehd->opt_header == NULL )
			{
				freePEHeaderData(pehd);
				return NULL;
			}

			return pehd;
		}

	public:
		static void SetUpTestCase()
		{
		}
};

TEST_F(HeaderParserLibPETest, test_getPEHeaderData_notAFile)
{
	const char* src = "tests/files/not-a.file";
	size_t start = 0;

	PEHeaderData* r = getPEHeaderData(src, start);

	EXPECT_EQ(r, nullptr);
}

TEST_F(HeaderParserLibPETest, test_getPEHeaderData_validPEFile)
{
	const char* src = pe_file;
	size_t start = 0;

	PEHeaderData* r = getPEHeaderData(src, start);

	EXPECT_EQ(r->image_dos_header->signature[0], 'M');
	EXPECT_EQ(r->image_dos_header->signature[1], 'Z');
	EXPECT_EQ(r->coff_header->Machine, 0x8664);
	EXPECT_EQ(r->opt_header->Magic, 0x20b);

	freePEHeaderData(r);
}

TEST_F(HeaderParserLibPETest, test_getPEHeaderData_validELFFile)
{
	const char* src = elf_file;
	size_t start = 0;

	PEHeaderData* r = getPEHeaderData(src, start);

	EXPECT_EQ(r, nullptr);

//	EXPECT_EQ(r->image_dos_header->signature[0], 'M');
//	EXPECT_EQ(r->image_dos_header->signature[1], 'Z');
//	EXPECT_EQ(r->coff_header->Machine, 0);
//	EXPECT_EQ(r->opt_header->Magic, 0);

//	freePEHeaderData(r);
}

TEST_F(HeaderParserLibPETest, test_hasCertificate)
{
	const char* src = pe_file;
	size_t start = 0;

	PEHeaderData* d = getPEHeaderData(src, start);
	bool r = PE_hasCertificate(d->opt_header);

	EXPECT_EQ(r, 0);

	freePEHeaderData(d);

	src = pe_file_with_cert;

	d = getPEHeaderData(src, start);
	r = PE_hasCertificate(d->opt_header);

	EXPECT_EQ(r, 1);

	freePEHeaderData(d);
}

TEST_F(HeaderParserLibPETest, test_getNumberOfCertificates)
{
	const char* src = pe_file;
	size_t start = 0;
	uint64_t start_file_offset = 0;
	size_t file_size = getSize(src);

	PEHeaderData* d = getPEHeaderData(src, start);
	memset(block_s, 0, BLOCKSIZE);
	uint8_t r = PE_getNumberOfCertificates(d->opt_header, start_file_offset, file_size, src, block_s);

	EXPECT_EQ(r, 0);

	freePEHeaderData(d);



	src = pe_file_with_cert;

	d = getPEHeaderData(src, start);
    memset(block_s, 0, BLOCKSIZE);
	r = PE_getNumberOfCertificates(d->opt_header, start_file_offset, file_size, src, block_s);

	EXPECT_EQ(r, 1);

	freePEHeaderData(d);
}

TEST_F(HeaderParserLibPETest, test_fillOfCertificateTable)
{
	const char* src = pe_file_with_cert;
	size_t start = 0;
    uint64_t start_file_offset = 0;
    size_t file_size = getSize(src);

	PEHeaderData* d = getPEHeaderData(src, start);
    memset(block_s, 0, BLOCKSIZE);
	uint8_t n = PE_getNumberOfCertificates(d->opt_header, start_file_offset, file_size, src, block_s);

	vector<PeAttributeCertificateTable> table;
	table.resize(n);

    memset(block_s, 0, BLOCKSIZE);
	PE_fillCertificateTable(table.data(), n, d->opt_header, start_file_offset, file_size, src, block_s);

	EXPECT_EQ(n, 1);
	EXPECT_EQ(table[0].wCertificateType, WIN_CERT_TYPE_PKCS_SIGNED_DATA);

	freePEHeaderData(d);
}

TEST_F(HeaderParserLibPETest, test_writeCertificatesToFile)
{
	const char* src = pe_file_with_cert;
	string dir = getTempDir("HeaderParserLibPETest");
	size_t start = 0;
	int s = 0;
	size_t cert_size;
	size_t file_size = getSize(src);
	uint64_t start_file_offset = 0;

	PEHeaderData* d = getPEHeaderData(src, start);
    memset(block_s, 0, BLOCKSIZE);
	uint8_t n = PE_getNumberOfCertificates(d->opt_header, start_file_offset, file_size, src, block_s);

	vector<PeAttributeCertificateTable> table;
	table.resize(n);

    memset(block_s, 0, BLOCKSIZE);
	PE_fillCertificateTable(table.data(), n, d->opt_header, start_file_offset, file_size, src, block_s);
    memset(block_s, 0, BLOCKSIZE);
	s = PE_writeCertificatesToFile(table.data(), n, dir.c_str(), file_size, src, block_s);

	string cert_name = dir+"/cert-0.der";
	cert_size = getSize(cert_name.c_str());

	EXPECT_EQ(n, 1);
	EXPECT_EQ(table[0].wCertificateType, WIN_CERT_TYPE_PKCS_SIGNED_DATA);
	EXPECT_EQ(s, 0);
	EXPECT_NE(cert_size, 0);

	freePEHeaderData(d);
	rmdir(dir.c_str());
}

TEST_F(HeaderParserLibPETest, test_PEcleanUp)
{
	PEHeaderData* d = getInitializedPEHeaderData();

	PE_cleanUp(d);
}

#endif
