import ImportMessage

def is_printable_char(character):
    """
    judge a character is whether a printable character
    :param character: a single character
    :return: True or False
    """
    if character >= 32 and character <= 127:
        return True
    if character == 10 or character == 13:
        return True
    return False


def text_binary_ngram(message,n):
    """
    if message is text or binary, use this function to complete n-gram
    :param message: single message(bytes type)
    :param n: the value of n in n-gram
    :return: the result of n-gram
    """
    if len(message)<n:
        return

    ngram_set = []
    j = 0

    for i in range(len(message)-n+1):
        ngram_set.append((message[i:i+n],j))
        j = j + 1

    return ngram_set


def mixed_ngram(message,n):
    """
    when message is mixed type, segmentation is used, and final n-gram used to the segmentation result
    :param message: mixed type message
    :param n: the value of n-gram
    :return: the result of n-gram
    """
    if len(message)<n:
        return

    ngram_set = []
    ngram_set_tmp = []
    seg_pos = []
    for i in range(len(message) - 1):
        if is_printable_char(message[i]) == True and is_printable_char(message[i + 1]) == False:
            seg_pos.append(i)
        if is_printable_char(message[i]) == False and is_printable_char(message[i + 1]) == True:
            seg_pos.append(i)
    ngram_set_tmp.append(message[0:seg_pos[0] + 1])
    for i in range(len(seg_pos) - 1):
        ngram_set_tmp.append(message[seg_pos[i] + 1:seg_pos[i + 1] + 1])
    ngram_set_tmp.append(message[seg_pos[i+1]+1:])

    k=0
    for i in range(len(ngram_set_tmp)):
        if len(ngram_set_tmp[i]) < n:
            continue
        for j in range(len(ngram_set_tmp[i])-n+1):
            ngram_set.append((ngram_set_tmp[i][j:j+n],k))
            k = k + 1
    return ngram_set


def get_type_ngram(message_type,type,n):
    """
    obtain one message type(text/bin/mixed)'s n-gram(with repetition)
    :param message_type: message list(the same type)
    :param type: text,bin,mixed
    :param n: the value of n-gram
    :return: the result of one message type's ngram
    """
    type_n_gram = []

    if type == 'text' or 'bin':
        for i in range(len(message_type)):
            type_n_gram.append(text_binary_ngram(message_type[i],n))

    if type == 'mixed':
        for i in range(len(message_type)):
            type_n_gram.append(mixed_ngram(message_type[i],n))

    return type_n_gram


def no_repetition_ngram(type_n_gram):
    """
    obatin the all ngram without repetition
    :param type_n_gram: the message's ngram list
    :return: no repetition ngram
    """
    no_repetition_n_gram = []

    for i in range(len(type_n_gram)):
        if type_n_gram[i] == None:
            continue
        for j in range(len(type_n_gram[i])):
            if type_n_gram[i][j] not in no_repetition_n_gram:
                no_repetition_n_gram.append(type_n_gram[i][j])

    return no_repetition_n_gram


def multi_N_ngram(message_type,type,minN,maxN):
    """
    under condition of the multiple n, obtain the ngram result of a messages list(the same type)
    :param message_type: a messages list
    :param type: text,bin or mixed
    :param minN: the min n in ngram
    :param maxN: the max n in ngram
    :return: the ngram result of a messages list
    """
    size = maxN - minN + 1
    some_type_ngram = [0] * size
    k = minN
    for i in range(size):
        some_type_ngram[i] = get_type_ngram(message_type,type,k)
        k = k + 1
    return some_type_ngram


def no_repetition_multi_N_ngram(some_type_ngram):
    """
    obtain the no repetition result of ngram of a messages list under different n
    :param some_type_ngram: the result of ngram of a message list under different n
    :return: no repetition multi N ngram
    """
    nrm_ngram = []
    for i in range(len(some_type_ngram)):
        nrm_ngram.append(no_repetition_ngram(some_type_ngram[i]))
    return nrm_ngram


if __name__ == '__main__':
    a = ImportMessage.import_file('S7_1.pcap')
    b = ImportMessage.import_file('http.pcap')
    c = a + b
    text_type, mixed_type, bin_type = ImportMessage.MessageClassifier(c)
    # mixed_type_ngram = get_type_ngram(mixed_type,'mixed',5)
    # nr_ngram = no_repetition_ngram(mixed_type_ngram)
    # for i in range(len(nr_ngram)):
    #     print(nr_ngram[i])
    # for i in range(len(mixed_type_ngram)):
    #     print(mixed_type_ngram[i])
    some_type_ngram = multi_N_ngram(mixed_type,'mixed',5,7)
    some_type_ngram = no_repetition_multi_N_ngram(some_type_ngram)
    for i in range(len(some_type_ngram)):
        print("")
        for j in range(len(some_type_ngram[i])):
            print(some_type_ngram[i][j])