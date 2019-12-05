import ImportMessage
import NPositionGram
import math
import copy

def get_sup_multi_ngram(some_type_ngram,nrm_ngram,allowrence):
    """
    obtain the sup of every ngram under the condition of different n
    :param some_type_ngram: ngram obtained from a messages list
    :param nrm_ngram: without repetition ngram
    :param allowrence: a allowed error
    :return: the sup of ngram
    """
    sup = []
    for i in range(len(nrm_ngram)):
        sup_tmp = [0] * len(nrm_ngram[i])
        for j in range(len(nrm_ngram[i])):
            for k in range(len(some_type_ngram[i])):
                if some_type_ngram[i][k] != None:
                    for l in range(len(some_type_ngram[i][k])):
                        if nrm_ngram[i][j][0] == some_type_ngram[i][k][l][0]:
                            if math.fabs(nrm_ngram[i][j][1] - some_type_ngram[i][k][l][1]) <= allowrence:
                                sup_tmp[j] = sup_tmp[j] + 1
                                break
        sup.append(sup_tmp)

    for i in range(len(sup)):
        for j in range(len(sup[i])):
            sup[i][j] = sup[i][j] / len(some_type_ngram[0])

    return sup


def get_ngram_sup(sup,nrm_ngram):
    """
    obtain (b'HTTP/',0.6),(ngram,sup)
    :param sup: sup metrix
    :param nrm_ngram: nrm_ngram
    :return: (ngram,sup)
    """
    ngram_sup = []
    for i in range(len(sup)):
        for j in range(len(sup[i])):
            ngram_sup.append((nrm_ngram[i][j][0],sup[i][j]))
    return ngram_sup


def cut_by_sup_threshold(ngram_sup,sup_threshold):
    """
    cut the (ngram,sup) which sup < sup_threshold
    :param ngram_sup: (ngram,sup)
    :param sup_threshold: parameter
    :return: (ngram,sup) with high sup
    """
    cut_ngram_sup = copy.deepcopy(ngram_sup)
    for i in range(len(ngram_sup)):
        if ngram_sup[i][1] < sup_threshold:
            cut_ngram_sup.remove(ngram_sup[i])
    return cut_ngram_sup


def del_non_close(cut_ngram_sup):
    close_ngram_tmp = copy.deepcopy(cut_ngram_sup)
    close_ngram = []
    for i in range(len(cut_ngram_sup)-1):
        for j in range(i+1,len(cut_ngram_sup)):
            if cut_ngram_sup[i][0] in cut_ngram_sup[j][0]:
                if cut_ngram_sup[i][1] <= cut_ngram_sup[j][1]:
                    if cut_ngram_sup[i] in close_ngram_tmp:
                        close_ngram_tmp.remove(cut_ngram_sup[i])
    for i in range(len(close_ngram_tmp)):
        close_ngram.append(close_ngram_tmp[i][0])
    return close_ngram


def get_close_ngram(type_message,type,minN,maxN,allowrence,sup_threshold):
    """
    obtain closed ngram list
    :param type_message: type message
    :param type: type
    :param minN: the min of n
    :param maxN: the max of n
    :param allowrence: a allowed error
    :param sup_threshold: the threshold of support degree
    :return: close ngram list
    """
    some_type_ngram = NPositionGram.multi_N_ngram(type_message,type,minN,maxN)
    nrm_ngram = NPositionGram.no_repetition_multi_N_ngram(some_type_ngram)
    sup = get_sup_multi_ngram(some_type_ngram,nrm_ngram,allowrence)
    ngram_sup = get_ngram_sup(sup,nrm_ngram)
    cut_ngram_sup = cut_by_sup_threshold(ngram_sup,sup_threshold)
    close_ngram = del_non_close(cut_ngram_sup)
    return close_ngram


if __name__ == '__main__':
    a = ImportMessage.import_file('S7_1.pcap')
    b = ImportMessage.import_file('http.pcap')
    c = a + b
    text_type, mixed_type, bin_type = ImportMessage.MessageClassifier(c)
    close_ngram = get_close_ngram(text_type,'text',4,7,10,0.4)
    print(len(close_ngram))
    for i in range(len(close_ngram)):
        print(close_ngram[i])