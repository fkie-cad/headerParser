#ifndef TESTS_DIRECTORY_RUNNER
#define TESTS_DIRECTORY_RUNNER

#include <cstdint>

#include <deque>
#include <filesystem>
#include <functional>
#include <vector>
#include <string>

#include "FileUtil.h"
#include "StringUtil.h"

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
		uint64_t file_count = 0;
		std::deque<std::string> result;

		std::string bin_path;
		std::string runner_name = "DirectoryRunner";

		std::string src_dir;
		std::vector<std::string> src_files;

	public:
		DirectoryRunner() = default;

		explicit DirectoryRunner(const std::string& bin_name);

		int parseArgs(int argc, char** argv);

		virtual ~DirectoryRunner();

		void run();

		void runList(const std::vector<std::string>& files);

		void runDirectory(const std::string& dir);

		void setRunnerName(const std::string& name);

	protected:
		virtual void fillFileCallback(const std::string& file) = 0;

		void printActFileInfo();
		void printActFileInfo(const std::string& file);
};

#endif
