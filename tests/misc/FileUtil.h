#ifndef UTILS_FILE_UTIL_H
#define UTILS_FILE_UTIL_H

#include <cstdint>

#include <filesystem>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace Utils
{
	class FileUtil
	{
		private:
			using FileCallback = std::function<void(const std::string&)>;

			using Condition = std::function<bool(const std::string&)>;

		public:
			/**
			 * Find files in directory with specified file_type.
			 *
			 * @param	dir_name string& the directory to search (recursive if #recursive_search is true)
			 * @param	file_types set<string>& the list of file types to search for
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @return	vector<string> the file list
			 * @throws	runtime_error
			 */
			static std::vector<std::string>
			getFilesInDir(const std::string& dir, const std::set<std::string>& files, const bool recursive = true);

			/**
			 * Find files in directory with specified file_type.
			 *
			 * @param	dir_name string& the directory to search (recursive if #recursive_search is true)
			 * @param	condition Condition condition, to choose or skip a file
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @return	vector<string> the file list
			 * @throws	runtime_error
			 */
			static std::vector<std::string>
			getFilesInDir(const std::string& dir_name, const Condition& condition, const bool recursive = true);

			/**
			 * Find files in directory with specified file_type and call back on each file.
			 *
			 * @param	dir string the directory to search (recursive if #recursive_search is true)
			 * @param	cb FileCallback the callback(string) called on each found file
			 * @param	c Condition condition, to choose or skip a file
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @throws	runtime_error
			 */
			static void actOnFilesInDir(const std::string& dir_path, const FileCallback& cb, const Condition& c,
										const bool recursive = true);

			/**
			 * Find files in directory with specified file_type and call back on each file.
			 *
			 * @param	dir string the directory to search (recursive if #recursive_search is true)
			 * @param	cb FileCallback the callback(string) called on each found file
			 * @param	types vector<string>& the list of file types to search for
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @throws	runtime_error
			 */
			static void actOnFilesInDir(const std::string& dir, const FileCallback& cb,
										const std::set<std::string>& types,
										const bool recursive = true);

			/**
			 * Find files in directory with specified file_type and call back on each file.
			 *
			 * @param	dir string the directory to search (recursive if #recursive_search is true)
			 * @param	cb FileCallback the callback(string) called on each found file
			 * @param	types vector<string>& the list of file types to search for
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @throws	runtime_error
			 */
			static void actOnFilesInDirWithBlackList(const std::string& dir, const FileCallback& cb,
													 const std::set<std::string>& types,
													 const bool recursive = true);

			/**
			 * Count files in a given directory structure.
			 *
			 * @param	directory string the directory path
			 * @param	set<string> file_types
			 * @param	c bool condition whether to whitelist or blacklist the given file types
			 * @param	recursive bool flag for recursive directory search
			 * @return	uint64_t file_count
			 * @throws	runtime_error
			 */
			static uint64_t countFiles(const std::string& dir, const std::set<std::string>& types, bool c = true, bool recursive = true);

			/**
			 * Count files in a given directory structure.
			 *
			 * @param	directory string the directory path
			 * @param	condition Condition a condition to skip/use files to count
			 * @param	recursive bool flag for recursive directory search
			 * @return	uint64_t file_count
			 * @throws	runtime_error
			 */
			static uint64_t countFiles(const std::string& dir_name, const Condition& condition, bool recursive = true);

			static std::string getFileName(const std::string&);

			static size_t getFileSizePOSIX(const std::string&);

			static size_t getFileSize(const std::string&);

			static std::vector<std::string> fileToVectorOfLines(const std::string& src);

			static bool fileExists(const std::string& path);

			static bool dirExists(const std::string& path);

			static int mkdir_p(const std::string& path);

			static std::string getTempFile(const std::string& prefix, const std::string& type = "");

			static std::string getTempDir(const std::string& prefix);

			/**
			 * Execute command and put output into vector<string>.
			 *
			 * @param	command string& the command
			 * @return	vector<string>
			 */
			static std::vector<std::string> exec(const std::string& command);

			static void exec(const std::string& command, std::vector<std::string>& result);

//			static void exec(const std::string& command, std::unique_ptr<FILE, decltype(&pclose)>& pipe);

			static void copy(const std::string& from, const std::string& to);

			static std::string expandPath(const char* src);

			static std::string expandPath(const std::string& src);

			static std::filesystem::path expandPath(std::filesystem::path in);

			static void createRandomBytes(size_t size, std::vector<uint8_t>& values);

			static void createRandomFile(const std::string& file_src, size_t size);

			/**
			 * Create a binary file out of given bytes
			 *
			 * @param file_src string& the file path
			 * @param bytes vector<uint8_t> the bytes to create the file of
			 */
			static void createBinaryFile(const std::string& file_src, const std::vector<uint8_t>& bytes);

		private:
//			static bool isWhiteListed(const std::set<std::string>& file_types, const std::string& extension);

//			static bool isNotBlackListed(const std::set<std::string>& file_types, const std::string& extension);
	};
}

#endif
