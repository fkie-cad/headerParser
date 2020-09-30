#include <iostream>

#include "DirectoryRunner.h"

#include "FileUtil.h"
#include "StringUtil.h"

using namespace std;
namespace fs = filesystem;

using namespace Utils;

DirectoryRunner::DirectoryRunner(const std::string& bin_name)
{
	std::filesystem::path root = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
	bin_path = root.string() + "/build/" + bin_name;
}

DirectoryRunner::~DirectoryRunner()
{}

void DirectoryRunner::printActFileInfo()
{
	++file_count;
	cout << LINE_UP << LINE_CLEAR << LINE_RETURN; // for "i / file_list_size"
	cout << "File: " << file_count << " / " << nr_of_files << " ("
		 << (int) ((float) file_count / nr_of_files * 100) << "%)"
		 //				 <<" : " << fs::path(file).filename()
		 << endl;
}

void DirectoryRunner::printActFileInfo(const string& file)
{
	++file_count;
	cout << LINE_UP << LINE_CLEAR << LINE_RETURN; // for "i / file_list_size"
	cout << "File: " << file_count << " / " << nr_of_files << " ("
		 << (int) ((float) file_count / nr_of_files * 100) << "%)"
		 				 <<" : " << fs::path(file).filename()
		 << endl;
}

void DirectoryRunner::run()
{
	if ( !src_dir.empty() )
		runDirectory(src_dir);
	else if ( !src_files.empty() )
		runList(src_files);
}

void DirectoryRunner::runList(const vector<string>& files)
{
	nr_of_files = files.size();
	cout << "number of files : " << nr_of_files << "\n\n\n";

	for ( const string& f : files )
		fillFileCallback(f);

	cout << endl;
	printf("result (%lu/%lu):\n", result.size(), nr_of_files);
	for ( const string& r : result )
		cout << r << ", ";
	cout << endl;
}


void DirectoryRunner::runDirectory(const string& dir)
{
	cout << "counting files in \"" << dir << "\" ...\n";
	nr_of_files = FileUtil::countFiles(dir, {}, true, true);
	cout << "number of files : " << nr_of_files << "\n\n\n";

	set<string> types = {};
	auto isWhiteListed = [&types](const string& file) -> bool {
		if ( types.empty()) return true;
		fs::path p(file);
		return types.find(p.extension()) != types.end();
	};

	FileUtil::actOnFilesInDir(dir, bind(&DirectoryRunner::fillFileCallback, this, placeholders::_1),
							  isWhiteListed, true);

	cout << endl;
	printf("result (%lu/%lu):\n", result.size(), nr_of_files);
	for ( const string& r : result )
		cout << r << ", ";
	cout << endl;
}

int DirectoryRunner::parseArgs(int argc, char** argv)
{
	if ( argc < 3 )
	{
		printf("Usage: %s -d|-f a/dir/path|file0 file1 ...\n", runner_name.c_str());
		printf("Example: %s -d a/dir/path\n", runner_name.c_str());
		printf("Example: %s -f file0 file1 ...\n", runner_name.c_str());
		return -1;
	}

	string argv1 = argv[1];

	if ( argv1 == "-d" )
		src_dir = argv[2];

	if ( argv1 == "-f" )
	{
		for ( int i = 2; i < argc; i++ )
		{
			string file = argv[i];
			if ( !fs::exists(file) || !fs::is_regular_file(file) )
			{
				cout << file + " not a file!"<<endl;
				exit(0);
			}
			src_files.emplace_back(file);
		}
	}

	if ( !src_dir.empty() && (!fs::exists(src_dir) || !fs::is_directory(src_dir)) )
	{
		cout << src_dir + " not a directory!"<<endl;
		return -2;
	}

	return 0;
}

void DirectoryRunner::setRunnerName(const std::string& name)
{
	runner_name = name;
}
