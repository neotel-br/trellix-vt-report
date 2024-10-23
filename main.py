from argparse import ArgumentParser
from os import path
from requests import get
from pandas import read_csv


VIRUSTOTAL_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files"
HEADERS = {}


def main():
    parser = ArgumentParser()
    parser.add_argument("-i", "--input", action="store", required=True,
                        help="arquivo de entrada gerado do Trellix em csv")
    parser.add_argument("-a", "--apikey", action="store", required=True,
                        help="chave de api para o virustotal.com")
    args = parser.parse_args()
    print(path.abspath(args.input), args.apikey)


if __name__ == "__main__":
    main()
