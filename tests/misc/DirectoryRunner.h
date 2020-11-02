#ifndef TESTS_DIRECTORY_RUNNER
#define TESTS_DIRECTORY_RUNNER

#include <cstdint>

#include <deque>
#include <filesystem>
#include <vector>
#include <string>

#include "ThreadPool.h"

class DirectoryRunner
{
	protected:
		using FileCallback = std::function<void(const std::string&)>;
		using Condition = std::function<bool(const std::string&)>;

		const std::string LINE_UP = "\e[A";
//		const std::string LINE_CLEAR = "[[2K";
		const std::string LINE_CLEAR = "\33[2K";
		const std::string LINE_RETURN = "\r";
		uint64_t nr_of_files = 0;
//		uint64_t file_count = 0;
		std::atomic_uint_fast64_t file_count = 0;
		std::deque<std::string> result;

		bool recursive = false;

		std::string bin_path;
		std::string runner_name = "DirectoryRunner";

		std::string src_dir;
		std::vector<std::string> src_files;

		bool threaded = false;
		uint32_t thread_pool_size = 0;
		Utils::ThreadPool<int> thread_pool;
		std::mutex io_lock;
		std::mutex stdio_lock;

	public:
		DirectoryRunner() = default;

		explicit DirectoryRunner(const std::string& bin_name);

		int parseArgs(int argc, char** argv);

		virtual ~DirectoryRunner();

		void run();

		void runList(const std::vector<std::string>& files);

		virtual
		void runDirectory(const std::string& dir);

		virtual
		void runDirectoryT(const std::string& dir);

		void setRunnerName(const std::string& name);

	protected:
		virtual int fillFileCallback(const std::string& file, void* params) = 0;

		virtual void fillFileCallbackT(const std::string& file, void* params);

		virtual void printUsage();
		virtual void printHelp();

		void printActFileInfo();
		void printFileInfo(const std::string& file);

};

#endif
