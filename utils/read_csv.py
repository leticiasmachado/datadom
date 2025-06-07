import pandas as pd

# função para ler datasets sem cabeçalho
def read_single_column_domains(file_path):
    df = pd.read_csv(file_path, header=None)  # lendo o arquivo sem cabeçalho
    return df[0].tolist()  # retorna a primeira coluna como lista

# função para ler datasets sem cabeçalho e com a segunda coluna contendo domínios
def read_second_column_domains(file_path):
    df = pd.read_csv(file_path, header=None, usecols=[1])  # usando a segunda coluna (índice 1)
    return df[1].tolist()  # retorna a segunda coluna como lista