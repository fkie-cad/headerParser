#ifndef TESTS_MISC_RAW_HEADER_DATA_PARSER
#define TESTS_MISC_RAW_HEADER_DATA_PARSER

#include <regex>
#include <string>
#include <vector>

#include "../../src/stringPool.h"
#include "../../src/HeaderData.h"

#include "StringUtil.h"

class RawHeaderDataParser
{
	public:
		static
		HeaderData* parseRawBasicData(const std::vector<std::string>& output)
		{
			std::string headertype;
			uint8_t bitness = 0;
			uint8_t endian = 0;
			std::string cpu_arch;
			std::string machine;
			std::regex e("( \\()(\\d){1,10}(\\))");
			std::smatch m;
			int code_regions_started = 0;
			size_t output_ln = output.size();
			size_t code_region_i = 0;
			std::vector <std::tuple<char*, uint64_t, uint64_t>> regions;
			size_t i;

			for ( i = 0; i < output_ln; i++ )
			{
				std::string l = output[i];
//				cout << l<<endl;

				if ( code_regions_started == 0 && l.find("coderegions:") != std::string::npos )
				{
					code_regions_started = 1;
					continue;
				}

				string code_r_id_str = "("+to_string(code_region_i+1)+")";
//				if ( code_regions_started == 1 && regex_search(l, m, e))
				if ( code_regions_started == 1 && l.find(code_r_id_str) == 1)
				{
					if ( l.find('(') == 1 )
					{
						if ( l.size() < 49 and i < output_ln - 1 )
						{
							l += "\n" + output[i + 1];
							i++;
						}
						size_t first_cpt = l.find(')');
                        size_t last_opt = l.rfind('(');
                        size_t n_s = l.rfind(':') - (first_cpt + 2);
						std::string name = l.substr(first_cpt + 2, n_s);
						std::vector<std::string> values;
						Utils::StringUtil::split(l.substr(last_opt), ' ', values);
						uint64_t start = stoul(values[1], nullptr, 16);
						uint64_t end = stoul(values[3], nullptr, 16);

						size_t name_ln = name.size();
						char* name_c = (char*) malloc(sizeof(char) * name_ln + 1);
						memcpy(name_c, &name[0], sizeof(char) * name_ln);
						name_c[name_ln] = 0;

//						cout << code_region_i<<endl;
//						cout << " - name: "<<name<<" : "<<"(0x"<<hex<<start<<":0x"<<end<<")"<<dec<<endl;
//						cout << " - name_c: "<<name_c<<" : "<<"(0x"<<hex<<start<<":0x"<<end<<")"<<dec<<endl;
//						cout << "name: "<<code_region.name<<" : "<<"(0x"<<hex<<code_region.start<<":0x"<<code_region.end<<")"<<dec<<endl;

						regions.emplace_back(std::tuple<char*, uint64_t, uint64_t>(name_c, start, end));

						code_region_i++;
					}
                    continue;
				}
				if ( !l.compare(0, 10, "headertype") )
				{
					headertype = l.substr(12);
					code_regions_started = 2;
				}
				else if ( !l.compare(0, 7, "bitness") )
				{
					std::string t = l.substr(9, 2);
					bitness = stoul(t, nullptr, 10);
				}
				else if ( !l.compare(0, 6, "endian") )
				{
					std::string t = l.substr(8);
					if ( t == "little" ) endian = 1;
					else if ( t == "big" ) endian = 2;
				}
				else if ( !l.compare(0, 7, "Machine") )
				{
					machine = l.substr(9);
				}
				else if ( !l.compare(0, 8, "CPU_arch") )
				{
					cpu_arch = l.substr(10);
				}
			}

			size_t machine_str_ln = machine.size();
			char* machine_c = (char*) malloc(sizeof(char) * machine_str_ln + 1);
			memcpy(machine_c, &machine[0], sizeof(char) * machine_str_ln);
			machine_c[machine_str_ln] = 0;

//			cout << "cpu_full_str_ln: '"<<cpu_full_str_ln<<"'"<<endl;
//			cout << "Machine: '"<<cpu_arch_full<<"'"<<endl;
//			cout << "CPU_arch_full_c: '"<<cpu_arch_full_c<<"'"<<endl;

			HeaderData* data = new HeaderData;
			data->headertype = findHeaderTypeId(&headertype[0]);
			data->bitness = bitness;
			data->endian = endian;
			data->CPU_arch = findCPUArchId(&cpu_arch[0]);
			data->Machine = machine_c;
			data->code_regions_size = code_region_i;
			data->code_regions = (CodeRegionData*) malloc(code_region_i * sizeof(CodeRegionData));

			for ( i = 0; i < code_region_i; i++ )
			{
				data->code_regions[i].name = get<0>(regions[i]);
				data->code_regions[i].start = get<1>(regions[i]);
				data->code_regions[i].end = get<2>(regions[i]);
			}

			return data;
		}

	private:
		static
		uint8_t findHeaderTypeId(const char* ht)
		{
			for ( uint8_t i = 0; i < HEADER_TYPES_SIZE; i++ )
			{
				if ( strcmp(header_type_names[i], ht) == 0 )
					return i;
			}

			return 0;
		}

		static
		uint8_t findCPUArchId(const char* an)
		{
			for ( uint8_t i = 0; i < ARCHITECTURE_NAMES_SIZE; i++ )
			{
				if ( strcmp(architecture_names[i], an) == 0 )
					return i;
			}
			return 0;
		}
};

#endif
