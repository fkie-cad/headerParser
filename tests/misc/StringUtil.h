#ifndef UTILS_STRING_UTIL_H
#define UTILS_STRING_UTIL_H

#include <algorithm>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace Utils
{
	class StringUtil
	{
		public:

			/**
			 * Checks if a string starts with a prefix and stops immediately, if  failing.
			 * Better performance than s.find(preifx)==0 checks.
			 * Could also be done with !s.compare(0,prefix.size(),prefix).
			 *
			 * @param s
			 * @param prefix
			 * @return
			 */
			static
			bool startsWith(std::string s, std::string prefix)
			{
				size_t n = prefix.size();
				if ( s.size() < n )
					return false;
				for ( size_t i = 0; i < n; i++ )
				{
					if ( s[i] != prefix[i] )
						return false;
				}
				return true;
			}

			/**
			 * Convert int to hex string,
			 * with the width of the int type.
			 *
			 * @param	i T the int to convert
			 * @param	prefix string a prefix to set
			 */
			template<typename T>
			static std::string intToHex(T i, const std::string& prefix="")
			{
				std::stringstream ss;
				ss << prefix;
				ss.fill('0');
				ss.width(sizeof(T)*2);
				ss << std::hex << +i;
				return ss.str();
			}

			/**
			 * Convert int to hex string.
			 *
			 * @param	i T the int to convert
			 * @param	w uint8_t the width of the string
			 * @param	prefix string a prefix to set
			 */
			template< typename T >
			static std::string intToHex(T i, uint8_t w, const std::string& prefix="")
			{
				std::stringstream ss;
				ss << prefix;
				ss.fill('0');
				ss.width(w);
				ss << std::hex << +i;
				return ss.str();
			}

			/**
			 * Replace all occurrences of some string with another string in a haystack string.
			 *
			 * @param	haystack string& the haystack to search in
			 * @param	from string& the needle to find
			 * @param	to string the string to replace needle
			 */
			static void replaceAll(std::string& haystack, const std::string& needle, const std::string& to)
			{
				if ( needle.empty() )
					return;

				size_t start_pos = 0;
				while ( (start_pos = haystack.find(needle, start_pos)) != std::string::npos )
				{
					haystack.replace(start_pos, needle.length(), to);
					start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
				}
			}

			/**
			 * Split string into parts by delimiter.
			 *
			 * @param	s string& the string to split
			 * @param	delim char the splitting delimiter
			 * @param	elems vector<string> the splitted elements
			 */
			static void split(const std::string& s, char delim, std::vector<std::string> &elems)
			{
				std::stringstream ss;
				ss.str(s);
				std::string item;
				while (getline(ss, item, delim))
				{
					elems.push_back(item);
				}
			}

			/**
			 * Split string into vector(parts) by delimiter.
			 *
			 * @param	s string& the string to split
			 * @param	delim char the splitting delimiter
			 */
			static std::vector<std::string> split(const std::string &s, char delim)
			{
				std::vector<std::string> elems;
				split(s, delim, elems);
				return elems;
			}

			/**
			 * Parse string to boolean.
			 * Returns true, if values is "true" or > 0.
			 *
			 * @param	value string
			 * @return	bool
			 */
			static bool toBool(std::string value)
			{
				bool b = false;
				try
				{
					uint64_t v = stoul(value, nullptr, 10);
					b = (v != 0);
				}
				catch ( std::logic_error& e )
				{
					transform(value.begin(), value.end(), value.begin(), ::tolower);
					std::istringstream(value) >> std::boolalpha >> b;
				}
				return b;
			}

			/**
			 * Trim from start.
			 *
			 * @param	s string& the string to trim
			 */
			static inline std::string& ltrim(std::string &s)
			{
				s.erase(s.begin(), find_if(s.begin(), s.end(), not1(std::ptr_fun<int, int>(isspace))));
				return s;
			}

			/**
			 * Trim from end.
			 *
			 * @param	s string& the string to trim
			 */
			static inline std::string& rtrim(std::string &s)
			{
				s.erase(find_if(s.rbegin(), s.rend(),not1(std::ptr_fun<int, int>(isspace))).base(),s.end());
				return s;
			}

			/**
			 * Trim from both ends.
			 *
			 * @param	s string& the string to trim
			 */
			static inline std::string& trim(std::string &s)
			{
				return ltrim(rtrim(s));
			}

			/**
			 * Get random ASCII string.
			 *
			 * @param	size uint32_t the length of the string
			 */
			static std::string randomString(uint32_t size)
			{
				std::stringstream name;
				for ( uint32_t i = 0; i < size; i++ )
				{
					uint8_t c = randRange(65,90);
					name << c;

				}
				return name.str();
			}

			/**
			 * Remove non digit characters of string and create a new one.
			 *
			 * @param	input string&
			 * @param	base int the number base. Supported are 10 (default), 2 and 16.
			 * @return 	string
			 */
			static std::string removeNonDigits(const std::string& input, int base=10)
			{
				std::string result;
				if ( base == 10 ) copy_if(input.begin(), input.end(), back_inserter(result), isDecDigit);
				else if ( base == 16 ) copy_if(input.begin(), input.end(), back_inserter(result), isHexDigit);
				else if ( base == 2 ) copy_if(input.begin(), input.end(), back_inserter(result), isBinDigit);

				return result;
			}

			/**
			 * Crop string if it's longer than max_size.
			 * ?? No difference to substr ??
			 *
			 * @param	s string& the string to crop
			 * @param	max_size sizt_t the max size of the string
			 * @return
			 */
			static std::string crop(std::string s, size_t max_size)
			{
				if ( s.size() > max_size )
				{
					s.resize(max_size);
				}

				return s;
			}

			/**
			 * Check if char is decimal digit.
			 *
			 * @param	ch char
			 * @return 	bool
			 */
			static inline bool isDecDigit(char ch)
			{
				return '0' <= ch && ch <= '9';
			}

			/**
			 * Check if char is hexadecimal digit.
			 *
			 * @param	ch char
			 * @return 	bool
			 */
			static inline bool isHexDigit(char ch)
			{
				return ( '0' <= ch && ch <= '9' ) || ( 'a' <= ch && ch <= 'f' ) || ( 'A' <= ch && ch <= 'F' );
			}

			/**
			 * Check if char is binary digit.
			 *
			 * @param	ch char
			 * @return 	bool
			 */
			static inline bool isBinDigit(char ch)
			{
				return ( '0' <= ch && ch <= '1' );
			}

		private:
			/**
			 * Generate random Number in range min, max.
			 *
			 * @param	min int64_t the min random value
			 * @param	max int64_t the max random value
			 * @retrun	int64_t
			 */
			static int64_t randRange(int64_t min, int64_t max)
			{
				std::random_device rd;
				std::mt19937 gen(rd());
				std::uniform_int_distribution<int64_t> dist(min, max);

				return dist(gen);
			}
	};
}

#endif
