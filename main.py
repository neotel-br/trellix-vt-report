from argparse import ArgumentParser
from os import path
from time import sleep
from requests import get
from pandas import read_csv, concat
from json import dump
import glob
import csv


VIRUSTOTAL_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files"
HEADERS = {}


def main():
    parser = ArgumentParser()
    parser.add_argument("-i", "--input_folder", action="store", required=True,
                        help="pasta que contem os arquivos csv gerados no Trellix")
    parser.add_argument("-a", "--apikey", action="store", required=True,
                        help="chave de api para o virustotal.com")
    args = parser.parse_args()
    caminho = path.abspath(args.input_folder)

    arquivos = glob.glob(caminho + "/*.csv")

    dados = read_csv(arquivos[0])
    for arquivo in arquivos[1:]:
        dados = concat([dados, read_csv(arquivo)], ignore_index=True)

    dados_sem_duplicados = dados.drop_duplicates()
    hashes_unicos = dados_sem_duplicados["Target Hash"].loc[dados['Target Hash'] != ' ']

    resposta = None

    HEADERS = {'x-apikey': args.apikey, 'accept': 'application/json'}

    nome_arquivo = input("Digite o nome do arquivo csv final: ")

    inp = input(
        f"ESSE RELATORIO CONTEM: {len(hashes_unicos)} hashes. Deseja continuar?(Y/N): ")

    if inp.upper() == 'Y':
        for hash_arq in hashes_unicos:
            resposta = get(
                f"{VIRUSTOTAL_FILE_ENDPOINT}/{hash_arq}", headers=HEADERS)

            print(resposta.status_code)

            if resposta.status_code != 200:
                continue

            print(hash_arq)
            resultado_sem_filtro = resposta.json()['data']['attributes']
            resultado = {}

            resultado["Possível Tipo de Ameaça"] = "N/A" if "popular_threat_classification" not in resultado_sem_filtro else resultado_sem_filtro['popular_threat_classification']['suggested_threat_label']
            resultado["Número de detecções maliciosas"] = resultado_sem_filtro['last_analysis_stats']['malicious']
            resultado["Número de detecções não-maliciosas"] = resultado_sem_filtro['last_analysis_stats']['harmless']
            resultado["Número de não detecções"] = resultado_sem_filtro['last_analysis_stats']['undetected']

            dados_sem_duplicados_dict = dados_sem_duplicados.to_dict('index')

            for _, v in dados_sem_duplicados_dict.items():
                if (v["Target Hash"] == hash_arq):
                    v["Possível Tipo de Ameaça"] = resultado["Possível Tipo de Ameaça"]
                    v["Número de detecções maliciosas"] = resultado["Número de detecções maliciosas"]
                    v["Número de detecções não-maliciosas"] = resultado["Número de detecções não-maliciosas"]
                    v["Número de não detecções"] = resultado["Número de não detecções"]
                else:
                    v["Possível Tipo de Ameaça"] = "N/A"
                    v["Número de detecções maliciosas"] = 0
                    v["Número de detecções não-maliciosas"] = 0
                    v["Número de não detecções"] = 0

        dados = [v for _, v in dados_sem_duplicados_dict.items()]

        with open(nome_arquivo, 'w', newline="") as f:
            campos = dados[0].keys()
            escritor_csv = csv.DictWriter(f, fieldnames=campos)

            escritor_csv.writeheader()
            escritor_csv.writerows(dados)
    else:
        print("Relatório cancelado")


if __name__ == "__main__":
    main()
