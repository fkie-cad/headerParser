import os
import subprocess
import unittest
from collections import defaultdict

from src import header_parser


class HeaderParserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._test_file_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
        cls._test_binary_src = os.path.join(cls._test_file_dir, 'testfile')

    def test_directory(self):
        directory = 'files'
        self.start(directory)

    def start(self, directory):
        cpt = sum([len(files) for r, d, files in os.walk(directory)])
        print("number of files : %d" % cpt)
        i = 1

        result = []

        for root, subdirs, files in os.walk(directory):
            print('--\nroot = ' + root)

            for subdir in subdirs:
                print('\t- subdirectory ' + subdir)

            for filename in files:
                print('\r - - %d / %d (%d%% ): %s' % (i, cpt, (1.0 * i / cpt * 100.0), filename), end='')
                p = os.path.join(root, filename)
                i += 1

                if self.is_rom(p):
                    result.append(p)
                # if self.is_unknown_pe_machine(p):
                #     result.append(p)
                # if self.is_mach_o(p):
                #     result.append(p)
                # if self.has_zero_timestamp(p):
                #     result.append(p)
                # if self.no_dos_stub(p):
                #     result.append(p)

                # if not self.run_header_parser_size_of_rva(p):
                #     result.append(p)

        print()
        print("result (%d/%s)" % (len(result), cpt))
        print(result)

    def test_run_header_parser(self):
        f = 'files/qappsrv.exe'
        sf = self.has_seg_fault(f)
        print(sf)

    def run_header_parser_size_of_rva(self, f):
        ln = self.parse_size_of_rva(f)
        print('ln')
        print(ln)
        if ln > 16:
            return False
        return True

    def has_header_data(self, p, hd_id, expected):
        hpd = header_parser.get_basic_info(p)
        return hpd[hd_id] == expected

    def is_art(self, p):
        needle = b'headertype: ART'
        output = self.get_header_parser_lines(p)

        for i in range(len(output) - 1):
            line = output[i]
            if needle in line:
                return True
        return False
        # return self.has_needle_in_output(p, b'headertype: ART', 1)

    def is_jar(self, p):
        return self.has_needle_in_output(p, b'headertype: Java', 1)

    def no_dos_stub(self, p):
        return self.has_needle_in_output(p, b'INFO: No DOS stub found', 2)

    def is_rom(self, p):
        return self.has_needle_in_output(p, b'Magic: 0x107', 2)

    def is_unknown_pe_machine(self, p):
        return self.has_needle_in_output(p, b'Machine: None', 2)

    def reached_end_of_file(self, p):
        return self.has_needle_in_output(p, b'INFO: Reached end of file.')

    def has_zero_timestamp(self, p):
        return self.has_needle_in_output(p, b'TimeDateStamp: Thu 01 Jan 1970 (0)', 2)

    def is_mach_o(self, p):
        return self.has_needle_in_output(p, b'headertype: Mach-O', 1)

    def has_needle_in_output(self, p, needle, i=1):
        output = self.get_header_parser_raw_output(p, i)
        # print(output)
        if needle in output:
            return True
        return False

    def run_header_parser_has_seg_fault(self, f):
        return self.has_seg_fault(f)

    def test_directory_compare_to_objdump(self):
        # directory = '/sbin'
        # directory = '/usr/bin/'
        # directory = '/usr/lib/'
        # directory = '/usr/lib32/'
        # directory = '/usr/lib64/'
        # directory = '/usr/sbin/'
        directory = '/opt'

        self.directory_compare_to_objdump(directory)

    def directory_compare_to_objdump(self, directory):
        bellyacher = []

        cpt = sum([len(files) for r, d, files in os.walk(directory)])
        print("number of files : %d" % cpt)
        i = 1

        for root, subdirs, files in os.walk(directory):
            print('--\nroot = ' + root)

            for subdir in subdirs:
                print('\t- subdirectory ' + subdir)

            for filename in files:
                print(' - - %d / %d (%d%% ): %s' % (i, cpt, (1.0 * i / cpt * 100.0), filename))
                p = os.path.join(root, filename)
                i += 1
                if not self._compare_file(p):
                    bellyacher.append(p)

        print("bellyacher (%d)" % len(bellyacher))
        print(bellyacher)

        assert len(bellyacher) == 0

    def _compare_file(self, f):
        hp = self._parse_x_regions_with_header_parser(f)
        od = self._parse_x_regions_with_objdump(f)

        if len(hp) != 0 or len(od) != 0:
            print("header parser")
            print(hp)
            print("object dump")
            print(od)

        return hp == od

    def test_file_compare_to_objdump(self):
        f = ''
        print(os.path.getsize(f))

        result = self._compare_file(f)

        assert result

    def has_seg_fault(self, file):
        output = self.get_header_parser_lines(file)

        print('output')
        print(output)

        return output == [b'']

    def parse_size_of_rva(self, file):
        output = self.get_header_parser_lines(file)

        ln = 0

        for i in range(len(output) - 1):
            line = output[i]
            # print(line)

            if b'INFO: unusual value of NumberOfRvaAndSizes' in line:
                colon = line.rfind(b':')
                ln = int(line[colon + 2:].decode('utf-8', 'backslashreplace').strip())
                break
            if b' - NumberOfRvaAndSizes' in line:
                opt = line.rfind(b'(')
                cpt = line.rfind(b')')
                ln = int(line[opt + 1:cpt].decode('utf-8', 'backslashreplace').strip())
                break

        return ln

    def get_header_parser_raw_output(self, file, i=1):
        parser_process = subprocess.Popen([self._get_header_parser_path(), file, '-i', str(i)], stdout=subprocess.PIPE)
        output = parser_process.communicate()[0]
        return output

    def get_header_parser_lines(self, file):
        output = self.get_header_parser_raw_output(file).split(b'\n')
        return output

    def _get_header_parser_path(self):
        this_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(this_dir, '../headerParser')

    def _parse_x_regions_with_header_parser(self, file):
        parser_process = subprocess.Popen([self._get_header_parser_path(), file], stdout=subprocess.PIPE)
        output = parser_process.communicate()[0].split(b'\n')

        return self._parse_x_regions(output)

    def _parse_x_regions(self, output):
        result = defaultdict(list)
        code_regions_started = False

        for i in range(len(output) - 1):
            line = output[i]

            # skip warnings
            if not code_regions_started:
                if b'coderegions:' in line:
                    code_regions_started = True
                continue
            if b'headertype:' in line:
                break

            if b'(' in line and line.index(b'(') == 1:
                if len(line) < 49 and i < len(output) - 1:
                    line = line + output[i + 1]

                first_cpt = line.index(b')')
                last_opt = line.rfind(b'(')
                last_colon = line.rfind(b':')
                name = line[first_cpt + 2:last_colon].decode('utf-8', 'backslashreplace').strip()
                values = line[last_opt:].split()
                start = int(values[1], base=16)
                end = int(values[3], base=16)

                result[name].append((start, end))

        return dict(result)

    def _parse_meta_data(self, output):
        result = {
            'headertype': '',
            'bitness': 0,
            'endian': 0,
            'cpu_arch': '',
            'cpu_arch_full': '',
        }

        for i in range(len(output) - 1):
            line = output[i]

            if b'headertype:' in line:
                result['headertype'] = line[12:]
            elif b'bitness:' in line:
                result['bitness'] = int(line[9:11])
            elif b'endian:' in line:
                t = line[8:]
                if t == 'little': result['endian'] = 1
                elif t == 'big': result['endian'] = 2
            elif b'CPU_arch_full:' in line:
                result['cpu_arch_full'] = line[15:]
            elif b'CPU_arch:' in line:
                result['cpu_arch'] = line[10:]

        return result

    def _parse_x_regions_with_objdump(self, file):
        """
        Alternative way (instead of the headerParser) to get x_regions.

        :return: a regions dictionary
        """
        result = defaultdict(list)

        parser_process = subprocess.Popen(["objdump", "-h", file], stdout=subprocess.PIPE)
        output = parser_process.communicate()[0].split(b'\n')
        # print('output: %s' % str(output))

        i = 0
        while i < len(output) - 1:
            line = output[i]

            if len(line.lstrip()) == 0:
                i = i + 1
                continue

            # print("line: %s" % line)
            if self._is_digit(line.lstrip()[0]) and (len(line) < 5 or self._has_numbers(output[i+1])):
                line = line + output[i+1]
                i = i+1

            tokens = line.split()
            if self._has_code(output[i + 1], tokens):
                # print('tokens: %s' % str(tokens))
                # print('output[i + 1]: %s' % str(output[i + 1]))
                tokens_len = len(tokens)
                size_id = tokens_len - 5
                start_id = tokens_len - 2
                start = int(tokens[start_id], base=16)
                end = int(tokens[start_id], base=16) + int(tokens[size_id], base=16)

                if tokens_len < 7:
                    name = ""
                elif tokens_len == 7:
                    name = tokens[1].decode('utf-8', 'backslashreplace').strip()
                elif tokens_len >= 8:
                    end_name_idx = tokens_len - 6
                    start_name = line.index(tokens[1])
                    end_name = line.index(tokens[end_name_idx], start_name) + len(tokens[end_name_idx])
                    name = line[start_name:end_name].decode('utf-8', 'backslashreplace').strip()

                result[name].append((start, end))
            i = i + 1

        return dict(result)

    def _has_numbers(self, s):
        # for c in input:
        #     print(c)
        #     if self._is_digit(c):
        #         return True
        # return False
        return any(self._is_digit(c) for c in s)

    def _is_digit(self, c):
        return 48 <= c <= 57

    def _has_code(self, next_line, tokens):
        return len(next_line) and (b"  CODE" in next_line or b", CODE" in next_line) and len(tokens) > 5
