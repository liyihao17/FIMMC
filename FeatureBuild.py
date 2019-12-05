import ImportMessage
import NPositionGram
import FrequentItemMining


def build_matrix(message_type,close_ngram):
    """
    build the feature matrix to represent the messages
    :param message_type: a message list
    :param close_ngram: closed ngram list
    :return: feature matrix
    """
    matrix = [[0 for i in range(len(close_ngram))] for j in range(len(message_type))]
    for i in range(len(message_type)):
        for j in range(len(close_ngram)):
            if close_ngram[j] in message_type[i]:
                matrix[i][j] = 1
    return matrix


if __name__ == '__main__':
    a = ImportMessage.import_file('S7_1.pcap')
    b = ImportMessage.import_file('http.pcap')
    c = a + b
    # c = ImportMessage.import_file('DNS_packet.pcap')
    text_type, mixed_type, bin_type = ImportMessage.MessageClassifier(c)
    close_ngram = FrequentItemMining.get_close_ngram(text_type,'text',3,7,10,0.5)
    for i in range(len(close_ngram)):
        print(close_ngram[i])
    print("")
    for message in mixed_type:
        print(message)
    feature_matrix = build_matrix(text_type,close_ngram)
    for i in range(len(feature_matrix)):
        print(feature_matrix[i])