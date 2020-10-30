#ifndef UTILS_FILE_UTIL_H
#define UTILS_FILE_UTIL_H

#include <cstdint>

#include <functional>
#include <set>
#include <string>
#include <vector>

namespace Utils
{
	class FileUtil
	{
		public:
			static bool FOLLOW_LINKS;
			static bool SKIP_HIDDEN_DIRS;
			static bool SKIP_HIDDEN_FILES;

			using FileCallback = std::function<void(const std::string&, void*)>;
			using Condition = std::function<bool(const std::string&)>;

		private:

		public:
			static
			std::string
			getVersion()
			{
				return "Version: 2.2.1";
			}

			/**
			 * Find files in directory with specified file_type.
			 * Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
			 * Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
			 * Hidden files may be skipped by setting FileUtil::SKIP_HIDDEN_FILES.
			 *
			 * @param	dir_name string& the directory to search (recursive if #recursive_search is true)
			 * @param	types set<string>& the (white) list of file types to search for, of empty set.
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @return	vector<string> the file list
			 * @throws	runtime_error
			 */
			static
			std::vector<std::string>
			getFilesInDir(const std::string& dir,
				 			const std::set<std::string>& types,
				 			bool recursive = true);

			/**
			 * Find files in directory skipping black listed file types
			 * Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
			 * Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
			 * Hidden files may be skipped by setting FileUtil::SKIP_HIDDEN_FILES.
			 *
			 * @param	dir_name string& the directory to search (recursive if #recursive_search is true)
			 * @param	types set<string>& the (black) list of file types to skip.
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @return	vector<string> the file list
			 * @throws	runtime_error
			 */
			static
			std::vector<std::string>
			getFilesInDirWithBlackList(const std::string& dir,
							  			const std::set<std::string>& types,
							  			bool recursive = true);

			/**
			 * Find files in directory with specified file_type.
			 * Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
			 * Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
			 * Hidden files may be skipped by the custom condition.
			 *
			 * @param	dir_name string& the directory to search (recursive if #recursive_search is true)
			 * @param	condition Condition condition, to choose or skip a file
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @return	vector<string> the file list
			 * @throws	runtime_error
			 */
			static
			std::vector<std::string>
			getFilesInDir(const std::string& path,
							const Condition& condition,
							bool recursive=true);

			/**
			 * Find files in directory with specified file_type and call back on each file.
			 * Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
			 * Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
			 * Hidden files may be skipped by the custom condition.
			 *
			 * @param	dir string the directory to search (recursive if #recursive_search is true)
			 * @param	cb FileCallback the callback(string) called on each found file
			 * @param	c Condition condition, to choose or skip a file
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @throws	runtime_error
			 */
			static
			int
			actOnFilesInDir(const std::string& dir_path,
					   			const FileCallback& cb,
					   			const Condition& c,
					   			bool recursive = true,
					   			void* params=NULL);

			/**
			 * Find files in directory with specified file_type and call back on each file.
			 * Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
			 * Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
			 * Hidden files may be skipped by setting FileUtil::SKIP_HIDDEN_FILES.
			 *
			 * @param	dir string the directory to search (recursive if #recursive_search is true)
			 * @param	cb FileCallback the callback(string) called on each found file
			 * @param	types vector<string>& the list of file types to search for
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @throws	runtime_error
			 */
			static
			void
			actOnFilesInDir(const std::string& dir,
								 const FileCallback& cb,
								 const std::set<std::string>& types,
								 bool recursive = true,
								 void* params=NULL);

			/**
			 * Find files in directory with specified file_type and call back on each file.
			 * Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
			 * Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
			 * Hidden files may be skipped by setting FileUtil::SKIP_HIDDEN_FILES.
			 *
			 * @param	dir string the directory to search (recursive if #recursive_search is true)
			 * @param	cb FileCallback the callback(string) called on each found file
			 * @param	types vector<string>& the list of file types that are black listed.
			 * @param	recursive bool do a "recursive" search including all subdirectories
			 * @throws	runtime_error
			 */
			static
			void
			actOnFilesInDirWithBlackList(const std::string& dir,
									 		  const FileCallback& cb,
											  const std::set<std::string>& types,
											  bool recursive = true,
											  void* params=NULL);

			/**
			 * Crop trailing slash of a path.
			 *
			 * @param	path string the path
			 * @return	string the (cropped) path
			 */
			static
			std::string
			cropTrailingSlash(const std::string& path);

			/**
			 * Count files in a given directory structure.
			 * Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
			 * Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
			 * Hidden files may be skipped by setting FileUtil::SKIP_HIDDEN_FILES.
			 *
			 * @param	directory string the directory path
			 * @param	set<string> file_types
			 * @param	c bool condition whether to whitelist or blacklist the given file types
			 * @param	recursive bool flag for recursive directory search
			 * @return	uint64_t file_count
			 * @throws	runtime_error
			 */
			static
			uint64_t
			countFiles(const std::string& dir,
					   const std::set<std::string>& types,
					   bool c = true,
					   bool recursive = true);

			/**
			 * Count files in a given directory structure.
			 * Hidden directories may be skipped by setting FileUtil::FOLLOW_LINKS.
			 * Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
			 * Hidden files may be skipped by the custom condition.
			 *
			 * @param	directory string the directory path
			 * @param	condition Condition a condition to skip/use files to count
			 * @param	recursive bool flag for recursive directory search
			 * @return	uint64_t file_count
			 * @throws	runtime_error
			 */
			static
			uint64_t
			countFiles(const std::string& dir_name,
			  			const Condition& condition,
			  			bool recursive = true);

			/**
			 * Get path of file without base name
			 *
			 * @param	path string the file path.
			 * @return	string
			 */
			static std::string getFileParentPath(const std::string& path);

			/**
			 * Get base name of file, with extension, without path.
			 *
			 * @param	path string the file path.
			 * @return	string
			 */
			static std::string getFileBaseName(const std::string& path);

			/**
			 * Get stem of file name
			 *
			 * @param	path string the file path.
			 * @return	string
			 */
			static std::string getFileNameStem(const std::string& path);

			/**
			 * Get type/extension of file name
			 *
			 * @param	path string the file path.
			 * @return	string
			 */
			static std::string getFileNameExt(const std::string& path);

			/**
			 * Get type/extension of file name with leading dot.
			 *
			 * @param	path string the file path.
			 * @return	string
			 */
			static std::string getFileNameFExt(const std::string& path);

			/**
			 * Get file size the POSIX way in bytes.
			 * Does not open the file.
			 * Faster than the fstream method.
			 *
			 * @param	path string the file source
			 * @return	uint32_t the file size
			 */
			static size_t getFileSizePOSIX(const std::string& file);

			/**
			 * Get the file size of a file in bytes.
			 * Using fstream tellg().
			 *
			 * @param	path string&& the file path
			 */
			static
			size_t getFileSize(const std::string& file);

			static
			bool isHiddenFile(const std::string& file);

			static
			bool isHiddenDir(const std::string& file);

			static
			std::vector<std::string> fileToVectorOfLines(const std::string& src);

			/**
			 * Count the number of lines in a text file.
			 *
			 * @param	file string&& the file path
			 * @return	size_t the number of lines
			 */
			static
			size_t countLines(const std::string& file);

			/**
			 * Check if a file exists.
			 *
			 * @param path
			 * @return
			 */
			static bool fileExists(const std::string& path);

			/**
			 * Check if a dir exists.
			 *
			 * @param path
			 * @return
			 */
			static bool dirExists(const std::string& path);

			/**
			 * Make dirs recursively.
			 * From: https://gist.github.com/JonathonReinhart/8c0d90191c38af2dcadb102c4e202950
			 *
			 * @param	dir string the dir path
			 */
			static int mkdir_p(const std::string& path);

			/**
			 * Create temp file in /tmp/prefixXXXXX.type and return its full path.
			 *
			 * @param prefix string& the name prefix
			 * @param type string& the file type
			 * @return the full file path
			 */
			static std::string getTempFile(const std::string& prefix,
								  			const std::string& type = "");

			/**
			 * Create temp directory in /tmp/prefix and return its full path.
			 *
			 * @param prefix string& the directory prefix
			 * @return the full directory path
			 */
			static std::string getTempDir(const std::string& prefix);

			/**
			 * Execute command and put output into vector<string>.
			 *
			 * @param	command string& the command
			 * @param	redirect_stderr bool redirect stderr into pipe as well
			 * @return	vector<string>
			 */
			static std::vector<std::string> exec(const std::string& command,
												bool redirect_stderr=true);

			/**
			 * Execute command and put output into result vector<string>.
			 *
			 * @param	command string& the command
			 * @param	result vector<string>
			 * @param	redirect_stderr bool redirect stderr into pipe as well
			 */
			static void exec(const std::string& command,
							std::vector<std::string>& result,
							bool redirect_stderr=true);

//			static void exec(const std::string& command, std::unique_ptr<FILE, decltype(&pclose)>& pipe);

			static void copy(const std::string& from,
							const std::string& to);

			static std::string expandPath(const char* src);

			static std::string expandPath(const std::string& src);

//			static std::filesystem::path expandPath(std::filesystem::path in);

			/**
			 * Create a vector of random bytes of size (bytes).
			 *
			 * @param size size_t the size in bytes
			 * @param values vector<uint8_t> the resulting bytes vector
			 */
			static void createRandomBytes(size_t size,
								 		std::vector<uint8_t>& values);

			/**
			 * Create a file with random bytes of size (bytes).
			 *
			 * @param file_src string the file path
			 * @param size size_t the size in bytes
			 */
			static void createRandomFile(const std::string& file_src,
										size_t size);

			/**
			 * Create a binary file out of given bytes
			 *
			 * @param file_src string& the file path
			 * @param bytes vector<uint8_t> the bytes to create the file of
			 */
			static
			void createBinaryFile(const std::string& file_src,
						 		const std::vector<uint8_t>& bytes);

			/**
			 * Get the directory of the current binary or of given pid.
			 *
			 * @param pid int the binaries pid. If 0, the current running binary is the choice.
			 * @return path to the current binary without its name
			 */
			static
			std::string getDirOfBinary(int pid=0);

		private:
//			static bool isWhiteListed(const std::set<std::string>& file_types, const std::string& extension);

//			static bool isNotBlackListed(const std::set<std::string>& file_types, const std::string& extension);
	};
}

#endif
