#include <iostream>
#include <set>

#include "DirectoryRunner.h"
#include "utils/FileUtil.h"


using namespace std;
using namespace Utils;
using namespace placeholders;
namespace fs = filesystem;


DirectoryRunner::DirectoryRunner(const std::string& bin_name)
{
    bin_path = Utils::FileUtil::getDirOfBinary() + "/" + bin_name;
//	std::filesystem::path root = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
//	bin_path = root.string() + "/build/" + bin_name;
}

DirectoryRunner::~DirectoryRunner()
{}

void DirectoryRunner::printActFileInfo()
{
	++file_count;
	stdio_lock.lock();
	cout << LINE_UP << LINE_CLEAR << LINE_RETURN; // for "i / file_list_size"
	cout << "File: " << file_count << " / " << nr_of_files << " ("
		 << (int) ((float) file_count / nr_of_files * 100) << "%)"
		 //				 <<" : " << fs::path(file).filename()
		 << endl;
	stdio_lock.unlock();
}

void DirectoryRunner::printFileInfo(const string& file)
{
	++file_count;
	stdio_lock.lock();
	cout << LINE_UP << LINE_CLEAR << LINE_RETURN; // for "i / file_list_size"
	cout << "File: " << file_count << " / " << nr_of_files << " ("
		 << (int) ((float) file_count / nr_of_files * 100) << "%)"
//		 				 <<" : " << fs::path(file).filename()
		 				 <<" : " << file
		 << endl;
	stdio_lock.unlock();
}

void DirectoryRunner::run()
{
	if ( !src_dir.empty() )
	{
		if ( threaded )
			runDirectoryT(src_dir);
		else
			runDirectory(src_dir);
	}
	else if ( !src_files.empty() )
		runList(src_files);
}

void DirectoryRunner::runList(const vector<string>& files)
{
	nr_of_files = files.size();
	cout << "number of files : " << nr_of_files << "\n\n\n";

	for ( const string& f : files )
		fillFileCallback(f, NULL);

	cout << endl;
	printf("result (%lu/%lu):\n", result.size(), nr_of_files);
	for ( const string& r : result )
		cout << r << ", ";
	cout << endl;
}


void DirectoryRunner::runDirectory(const string& dir)
{
	cout << "counting files in \"" << dir << "\" ...";
	nr_of_files = FileUtil::countFiles(dir, {}, true, recursive);
	cout << "\rnumber of files : " << nr_of_files << "\n\n\n";

	set<string> types = {};
	auto isWhiteListed = [&types](const string& file) -> bool {
		if ( types.empty()) return true;
		fs::path p(file);
		return types.find(p.extension()) != types.end();
	};

	FileUtil::actOnFilesInDir(dir, bind(&DirectoryRunner::fillFileCallback, this, _1, _2),
							  isWhiteListed, recursive);

	cout << endl;
	printf("result (%lu/%lu):\n", result.size(), nr_of_files);
	for ( const string& r : result )
		cout << r << ", ";
	cout << endl;
}

void DirectoryRunner::runDirectoryT(const string& dir)
{
	cout << "counting files in \"" << dir << "\" ...\n";
	nr_of_files = FileUtil::countFiles(dir, {}, true, recursive);
	cout << "number of files : " << nr_of_files << "\n\n\n";

	set<string> types = {};
	auto isWhiteListed = [&types](const string& file) -> bool {
		if ( types.empty()) return true;
		fs::path p(file);
		return types.find(p.extension()) != types.end();
	};

	thread_pool.setPoolSize(thread_pool_size);
	thread_pool.setLaunchPolicy(launch::async);


	FileUtil::actOnFilesInDir(dir, bind(&DirectoryRunner::fillFileCallbackT, this, _1, _2),
							  isWhiteListed, recursive);

	thread_pool.getResults();

	cout << endl;
	printf("result (%lu/%lu):\n", result.size(), nr_of_files);
	for ( const string& r : result )
		cout << r << ", ";
	cout << endl;
}

void DirectoryRunner::fillFileCallbackT(const string& file, void* params)
{
	thread_pool.add(&DirectoryRunner::fillFileCallback, this, file, params);
}

void DirectoryRunner::printUsage()
{
	printf("Usage: %s [-r] [-t x] -d|-f a/dir/path|file0 file1 ...\n", runner_name.c_str());
}

void DirectoryRunner::printHelp()
{
	printUsage();
	printf("\n");
	printf("Options:\n");
	printf(" -d:string : One or more source directories\n");
	printf(" -f:string : One or more source files\n");
	printf(" -t:uint16 : Number of threads\n");
	printf(" -r:int : recursive directory iteration\n");
	printf("\n");
	printf("Examples:\n");
	printf("$ %s -d a/dir/path\n", runner_name.c_str());
	printf("$ %s -f file0 file1 ...\n", runner_name.c_str());
}

int DirectoryRunner::parseArgs(int argc, char** argv)
{
	if ( argc > 1 && argv[1][0] == '-' && argv[1][1] == 'h' && argv[1][2] == 0 )
	{
		printHelp();
		return 0;
	}
	if ( argc < 3 )
	{
		printUsage();
		return -1;
	}
	int type_i = 1;
	int start_pi = 2;
	int i;
	char* arg;
	int type = 0;

	for (i = 1; i < argc-1; i++ )
	{
		arg = argv[i];
		if ( arg[0] == '-' )
		{
			if ( arg[1]=='t' && arg[2] == 0)
			{
				thread_pool_size = strtol(argv[i+1], nullptr, 0);
				threaded = thread_pool_size > 1;
				i++;
			}
			else if ( arg[1]=='d' && arg[2] == 0)
				type = 1;
			else if ( arg[1]=='f' && arg[2] == 0)
				type = 2;
			else if ( arg[1]=='r' && arg[2] == 0)
				recursive = true;
		}
		else
			break;
	}
	start_pi = i;
	if ( i >= argc )
	{
		printf("Error: No input path!\n");
		return 0;
	}

	printf("Threads: %s\n", (threaded)?"yes":"no");
	printf("thread_pool_size: %u\n", thread_pool_size);
	printf("recursive: %s\n", (recursive)?"yes":"no");

	if ( type == 1 )
		src_dir = argv[start_pi];

	if ( type == 2 )
	{
		for ( i = start_pi; i < argc; i++ )
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

const char* DirectoryRunner::getComparResult(bool r) const
{
    if ( r )
        return "passed";
    else
        return "failed";
}
