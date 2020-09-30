import sys

# from test_header_parser import HeaderParserTest
from compare_header_parser_to_lib import CompareHeaderParserToLib

python_majorversion = int(sys.version.split()[0].split('.')[0])
if python_majorversion != 3:
    print("This must be run under Python3!")
    sys.exit()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 %s a/dir/" % __file__)
        sys.exit()

    d = sys.argv[1]
    print('dir: %s' % d)

    # hp_test = HeaderParserTest()
    hp_test = CompareHeaderParserToLib()
    hp_test.start(d)

    sys.exit()
