import os
import subprocess

from src import header_parser


class CompareHeaderParserToLib:
    def __init__(self):
        test_dir = os.path.dirname(os.path.realpath(__file__))
        root_dir = os.path.dirname(test_dir)
        lib_src = os.path.join(root_dir, 'build/libheaderparser.so')

        self._test_file_dir = os.path.join(test_dir, 'data')
        self._test_binary_src = os.path.join(self._test_file_dir, 'testfile')
        header_parser.init(lib_src)

    def test_directory(self):
        directory = '/bin'

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

                if not self.are_equal(p):
                    result.append(p)

        print()
        print("result (%d/%s)" % (len(result), cpt))
        print(result)

    def are_equal(self, p):
        output = self.get_header_parser_raw_output(p).split(b'\n')
        hpd = self._parse_meta_data(output)
        x_regions = self._parse_x_regions(output)
        hpd['regions'] = x_regions
        hpd['regions_size'] = len(x_regions)
        hpd_lib = header_parser.get_basic_info(p)

        # print('output')
        # print(output)
        # print('')
        # print('hpd')
        # print(hpd)
        # print('hpd_lib')
        # print(hpd_lib)
        # print('hpd==hpd_lib: %i' % (hpd==hpd_lib))

        return hpd == hpd_lib

    def get_header_parser_raw_output(self, file, i=1):
        parser_process = subprocess.Popen([self._get_header_parser_path(), file, '-i', str(i)], stdout=subprocess.PIPE)
        output = parser_process.communicate()[0]
        return output

    def _get_header_parser_path(self):
        this_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(this_dir, '../build/headerParser')

    def _parse_x_regions_with_header_parser(self, file):
        parser_process = subprocess.Popen([self._get_header_parser_path(), file], stdout=subprocess.PIPE)
        output = parser_process.communicate()[0].split(b'\n')

        return self._parse_x_regions(output)

    def _parse_x_regions(self, output):
        # result = defaultdict(list)
        result = []
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
                    line = line + b'\n' + output[i + 1]

                first_cpt = line.index(b')')
                last_opt = line.rfind(b'(')
                last_colon = line.rfind(b':')
                name = line[first_cpt + 2:last_colon].decode('utf-8', 'backslashreplace').strip()
                values = line[last_opt:].split()
                start = int(values[1], base=16)
                end = int(values[3], base=16)

                result.append((name, start, end))
                # result[name].append((start, end))

                i += 1

        return result
        # return dict(result)

    def _parse_meta_data(self, output):
        result = {
            'headertype': '',
            'cpu': '',
            'cpu_full': '',
            'endian': 0,
            'bitness': 0,
        }

        for i in range(len(output) - 1):
            line = output[i]
            # print('line: %s' % line)

            if line.find(b'headertype:') == 0:
                result['headertype'] = line[12:].decode('utf-8')
            elif line.find(b'bitness:') == 0:
                # print('line[9:11]: %s' % line[9:line.index(b'-')])
                result['bitness'] = int(line[9:line.index(b'-')])
            elif line.find(b'endian:') == 0:
                t = line[8:]
                if t == b'little': result['endian'] = 1
                elif t == b'big': result['endian'] = 2
            elif line.find(b'CPU_arch_full:') == 0:
                result['cpu_full'] = line[15:].decode('utf-8')
            elif line.find(b'CPU_arch:') == 0:
                result['cpu'] = line[10:].decode('utf-8')

        return result
