# Trellix VirusTotal Daily

A ferramenta traz o relatório de ameaças da estação com base nos binários recebidos de .csv extraído da Trellix e cruzamento de hash com o site virustotal.com a partir de chamadas em sua API

## Requerimentos

### Relatório Trellix

O relatório no Trellix deve conter a coluna **SHA1**, **Threat Target File Path**, **Threat Target Host Name**(certifique-se de que esse campo exista na tabela).

1. Navegue até o computador afetado no Trellix;
2. Clique em Show Threat Events;
3. Clique em Action -> Choose colums:
  1. Pesquise por "SHA1"; Clique na entrada "Adaptive Threat Protection" -> File SHA1 Hash
  2. Pesquise por "path"; Clique na entrada "Threat Event Log" -> "Threat Target File Path"
  3. Pesquise por "host name"; Clique na entrada "Threat Event Log" -> "Threat Target Host Name"
4. Clique em Save;
5. Clique em Actions -> Export;
  1. Selecione **csv** em "File Format"
  2. Clique em Export;
  3. Salve-o no seu computador;

## Uso

```bash
python ./main.py --input arquivo.csv --apikey <SUA_CHAVE_DE_API_VIRUSTOTAL>
```

Um novo arquivo será gerado com o nome do computador. Utilize-o para tirar as conclusões sobre as ameaças detectadas no host e tomar as providências!

